import argparse
import json
import os
from pathlib import Path
import re
import sys
import time

from openai import APIConnectionError, APIError, APITimeoutError, OpenAI

API_BASE_URL = "http://localhost:11434/v1"
MODEL_NAME = "qwen3:4b-Instruct"
DEFAULT_ALERT_DIR = Path.home() / ".llm_pipeline"
DEFAULT_ALERT_DIR.mkdir(mode=0o700, exist_ok=True)
DEFAULT_ALERT_FILE = str(DEFAULT_ALERT_DIR / "llm_alerts.log")
DEFAULT_PROMPT_FILE = Path(__file__).with_name("prompt.txt")
ALLOWED_ATTACK_TYPES = {
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Brute-force authentication",
    "Directory or endpoint enumeration",
    "Command injection",
    "Automated vulnerability scanning",
    "Benign/normal traffic",
}

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOSTNAME_PATTERN = re.compile(
    r"\b[\w.-]+\.(?:acme|local|internal|corp|intranet)\b", re.IGNORECASE
)


def pseudonymize_logs(log_text):
    """Replace real IPs and internal hostnames with deterministic fakes.

    Returns (sanitized_text, reverse_map) so callers can de-pseudonymize.
    """
    ip_map = {}
    counter = [1]

    def _replace_ip(match):
        real_ip = match.group(0)
        if real_ip not in ip_map:
            ip_map[real_ip] = f"10.0.0.{counter[0]}"
            counter[0] += 1
        return ip_map[real_ip]

    sanitized = _IP_PATTERN.sub(_replace_ip, log_text)
    sanitized = _HOSTNAME_PATTERN.sub("host.example.net", sanitized)

    reverse_map = {fake: real for real, fake in ip_map.items()}
    return sanitized, reverse_map


def depseudonymize_findings(findings, reverse_map):
    """Restore original IPs in evidence and explanation fields."""
    if not reverse_map:
        return findings

    def _restore(text):
        for fake, real in reverse_map.items():
            text = text.replace(fake, real)
        return text

    restored = []
    for finding in findings:
        entry = dict(finding)
        entry["evidence"] = [_restore(e) for e in entry.get("evidence", [])]
        entry["explanation"] = _restore(entry.get("explanation", ""))
        restored.append(entry)
    return restored


SAMPLE_LOGS = """
192.168.1.10 - - [25/Feb/2026:10:00:01 +0100] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.10 - - [25/Feb/2026:10:00:03 +0100] "GET /assets/style.css HTTP/1.1" 200 351 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.15.42 - - [25/Feb/2026:10:05:12 +0100] "GET /.env HTTP/1.1" 404 153 "-" "python-requests/2.28.1"
10.0.15.42 - - [25/Feb/2026:10:05:13 +0100] "GET /admin/config.php HTTP/1.1" 404 153 "-" "python-requests/2.28.1"
10.0.15.42 - - [25/Feb/2026:10:05:14 +0100] "GET /backup.sql HTTP/1.1" 404 153 "-" "python-requests/2.28.1"
198.51.100.7 - - [25/Feb/2026:10:10:00 +0100] "GET / HTTP/1.1" 200 4500 "-" "sqlmap/1.5.2#dev (http://sqlmap.org)"
198.51.100.7 - - [25/Feb/2026:10:10:01 +0100] "GET /info.php HTTP/1.1" 404 230 "-" "Nikto/2.1.6"
192.168.1.105 - - [25/Feb/2026:10:15:32 +0100] "GET /products?category=1'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 500 453 "-" "Mozilla/5.0"
192.168.1.106 - - [25/Feb/2026:10:16:05 +0100] "GET /search?q=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E HTTP/1.1" 200 1205 "-" "Mozilla/5.0"
192.168.1.200 - - [25/Feb/2026:10:20:12 +0100] "GET /ping?ip=127.0.0.1+%3B+cat+%2Fetc%2Fpasswd HTTP/1.1" 200 567 "-" "Mozilla/5.0"
192.0.2.14 - - [25/Feb/2026:10:25:01 +0100] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0"
192.0.2.14 - - [25/Feb/2026:10:25:03 +0100] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0"
192.0.2.14 - - [25/Feb/2026:10:25:05 +0100] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0"
192.0.2.14 - - [25/Feb/2026:10:25:07 +0100] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0"
""".strip()


def load_prompt_template(prompt_file):
    path = Path(prompt_file)
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
    return path.read_text(encoding="utf-8", errors="replace")


def build_prompt(log_chunk, prompt_template):
    placeholder = "{{LOG_CHUNK}}"
    if placeholder in prompt_template:
        return prompt_template.replace(placeholder, log_chunk)
    return f"{prompt_template.rstrip()}\n\nAnalyze the following logs:\n{log_chunk}"


def analyze_logs_with_llm(log_chunk, prompt_template, client):
    prompt = build_prompt(log_chunk, prompt_template)

    for attempt in range(1, 4):
        result_text = ""
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": "Return valid JSON only.",
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                response_format={"type": "json_object"},
            )

            message = completion.choices[0].message
            result_text = (message.content or "").strip()
            if not result_text:
                print("Error: Received an empty response from the LLM.", file=sys.stderr)
                return None
            return json.loads(result_text)
        except (APIConnectionError, APITimeoutError, APIError) as connection_error:
            if attempt == 3:
                print(f"Error connecting to LLM API: {connection_error}", file=sys.stderr)
                return None
            time.sleep(1.0)
        except json.JSONDecodeError:
            print("Error: The LLM did not return valid JSON.", file=sys.stderr)
            if result_text:
                print("Raw output:", result_text, file=sys.stderr)
            return None


def normalize_finding(payload):
    if not isinstance(payload, dict):
        return None

    attack_type = payload.get("attack_type")
    if isinstance(attack_type, str):
        attack_type = attack_type.strip() or None
    else:
        attack_type = None

    malicious = bool(payload.get("malicious", False))
    if malicious and not attack_type:
        attack_type = "Automated vulnerability scanning"

    if attack_type not in ALLOWED_ATTACK_TYPES:
        attack_type = None

    raw_confidence = payload.get("confidence", 0.0)
    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    raw_evidence = payload.get("evidence")
    if isinstance(raw_evidence, list):
        evidence = [str(item).strip() for item in raw_evidence if str(item).strip()]
    elif raw_evidence is None:
        evidence = []
    else:
        text = str(raw_evidence).strip()
        evidence = [text] if text else []

    explanation = str(payload.get("explanation", "")).strip()

    return {
        "malicious": malicious,
        "attack_type": attack_type,
        "confidence": confidence,
        "evidence": evidence,
        "explanation": explanation,
    }


def validate_result(payload):
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        raw_findings = payload.get("findings", [])
    elif isinstance(payload, list):
        raw_findings = payload
    elif isinstance(payload, dict):
        raw_findings = [payload]
    else:
        return None

    findings = []
    for item in raw_findings:
        normalized = normalize_finding(item)
        if normalized is not None:
            findings.append(normalized)

    if not findings:
        findings = [{
            "malicious": False,
            "attack_type": "Benign/normal traffic",
            "confidence": 0.0,
            "evidence": [],
            "explanation": "No usable findings in the model output.",
        }]

    findings.sort(key=lambda entry: entry.get("confidence", 0.0), reverse=True)
    return {"findings": findings}


def read_last_lines(log_file, line_count):
    path = Path(log_file)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    return "".join(lines[-line_count:]).strip()


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze server logs using an OpenAI-compatible API.")
    parser.add_argument("--log-file", help="Path to a log file",
                        default="/var/log/apache2/dvwa_access.log")
    parser.add_argument("--lines", type=int, default=50, help="Number of last log lines to read")
    parser.add_argument("--stdin", action="store_true", help="Read logs from stdin")
    parser.add_argument("--sample", action="store_true", help="Use sample logs")
    parser.add_argument("--provider", choices=("ollama", "external"), default="ollama", help="LLM provider preset")
    parser.add_argument("--model", default=MODEL_NAME, help="LLM model name")
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible base URL (overrides provider default)")
    parser.add_argument("--api-key", default=None, help="API key (overrides provider default)")
    parser.add_argument("--prompt-file", default=str(DEFAULT_PROMPT_FILE), help="Path to prompt file")
    parser.add_argument("--alert-file", default=DEFAULT_ALERT_FILE, help="File for detected alerts")
    parser.add_argument("--pseudonymize", action="store_true",
                        help="Anonymize IPs and hostnames before sending to the LLM")
    return parser.parse_args()


def resolve_provider_settings(args):
    if args.provider == "ollama":
        base_url = args.base_url or "http://localhost:11434/v1"
        api_key = args.api_key or "ollama"
        return base_url, api_key

    base_url = args.base_url or "https://api.openai.com/v1"
    api_key = args.api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("An API key is required for provider 'external' (use --api-key or OPENAI_API_KEY).")
    return base_url, api_key


def resolve_log_chunk(args):
    if args.sample:
        return SAMPLE_LOGS
    if args.stdin:
        return sys.stdin.read().strip()
    if args.log_file:
        return read_last_lines(args.log_file, args.lines)
    return SAMPLE_LOGS


def main():
    args = parse_args()

    global API_BASE_URL, MODEL_NAME
    MODEL_NAME = args.model

    try:
        API_BASE_URL, api_key = resolve_provider_settings(args)
    except ValueError as value_error:
        print(str(value_error), file=sys.stderr)
        return 2

    client = OpenAI(base_url=API_BASE_URL, api_key=api_key)

    try:
        log_chunk = resolve_log_chunk(args)
        prompt_template = load_prompt_template(args.prompt_file)
    except FileNotFoundError as file_error:
        print(str(file_error), file=sys.stderr)
        return 2

    if not log_chunk:
        print("No log data found to analyze.", file=sys.stderr)
        return 2

    reverse_map = {}
    if args.pseudonymize:
        log_chunk, reverse_map = pseudonymize_logs(log_chunk)
        print("Pseudonymized log data before sending to LLM.")

    print("Analyzing logs...")
    analysis_result = analyze_logs_with_llm(log_chunk, prompt_template, client)
    validated = validate_result(analysis_result)

    if validated is None:
        return 1

    if reverse_map:
        validated["findings"] = depseudonymize_findings(
            validated["findings"], reverse_map
        )

    print("\n--- LLM Analysis Result ---")
    print(json.dumps(validated, indent=2, ensure_ascii=False))

    malicious_findings = [item for item in validated.get("findings", []) if item.get("malicious")]
    if malicious_findings:
        with open(args.alert_file, "a", encoding="utf-8") as handle:
            for finding in malicious_findings:
                handle.write(json.dumps(finding, ensure_ascii=False) + "\n")
        print(f"Saved {len(malicious_findings)} alert(s) to: {args.alert_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
