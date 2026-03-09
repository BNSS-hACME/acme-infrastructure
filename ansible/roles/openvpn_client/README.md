# openvpn_client

## Revoking a certificate

Certificates can be revoked via the Step CA using the `step ca revoke` command.
Revocation adds the certificate to the CRL, which OpenVPN checks on every new connection.

### By serial number (active revocation)

The serial number can be found with:

```bash
openssl x509 -noout -serial -in <cert.crt>
# or
step certificate inspect <cert.crt> | grep Serial
```

Then revoke:

```bash
step ca revoke <serial-number> \
  --ca-url https://auth.server.acme:9000 \
  --root /etc/step-ca/certs/root_ca.crt \
  --reason "reason string" \
  --reasonCode <0-10>
```

When run on `auth.server.acme`, the provisioner prompt appears interactively.
To script it non-interactively, pre-generate a token:

```bash
TOKEN=$(step ca token --revoke <serial-number> \
  --provisioner admin \
  --provisioner-password-file /etc/step-ca/password.txt \
  --ca-url https://auth.server.acme:9000 \
  --root /etc/step-ca/certs/root_ca.crt)
step ca revoke --token $TOKEN <serial-number>
```

### By certificate and key (mTLS revocation)

If you have the cert and key files, no provisioner token is needed:

```bash
step ca revoke \
  --cert <cert.crt> \
  --key <cert.key> \
  --ca-url https://auth.server.acme:9000 \
  --root /etc/step-ca/certs/root_ca.crt
```

### Reason codes

| Code | Name                 | Description                           |
| ---- | -------------------- | ------------------------------------- |
| 0    | Unspecified          | Default, no reason given              |
| 1    | KeyCompromise        | Key is believed to be compromised     |
| 2    | CACompromise         | Issuing CA has been compromised       |
| 3    | AffiliationChanged   | Affiliation/ownership changed         |
| 4    | Superseded           | Certificate is being replaced         |
| 5    | CessationOfOperation | CA is being decommissioned            |
| 6    | CertificateHold      | Temporary revocation                  |
| 8    | RemoveFromCRL        | Unrevoke a CertificateHold            |
| 9    | PrivilegeWithdrawn   | Right to represent entity was revoked |
| 10   | AACompromise         | Attribute authority compromised       |

> **Note:** Revocation by serial number is not supported for certificates issued
> via an OIDC provisioner — use `--cert` and `--key` instead.
