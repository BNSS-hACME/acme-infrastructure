LOG_FILE="/var/log/apache2/dvwa_access.log"
PIPELINE="/opt/llm_pipeline/basic_ai_pipeline.py"
inotifywait -m -e modify "$LOG_FILE" |
while read -r directory event filename; do
    python3 "$PIPELINE" --log-file "$LOG_FILE" --lines 50 --pseudonymize
done