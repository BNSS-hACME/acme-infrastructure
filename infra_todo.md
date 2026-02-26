# Keycloak + Nextcloud Integration ToDo

**DNS**
- Add `auth.server.acme` -> `10.0.50.13` to Ansible `unbound` role
- Add `nextcloud.acme` -> `10.0.50.12` to Ansible `unbound` role

**Certificates (StepCA)**
- Generate certs and place on `auth.server.acme` (Keycloak):
  - `/var/lib/keycloak/certs/tls.crt`
  - `/var/lib/keycloak/certs/tls.key`
- Ensure Keycloak cert files are readable by Keycloak (UID/GID 1000)
- Uncomment certificate variables in Keycloak `docker-compose.yml.j2`

- Generate certs and place on `cloud.server.acme` (Nextcloud):
  - `/var/lib/nextcloud/certs/tls.crt`
  - `/var/lib/nextcloud/certs/tls.key`
- Place StepCA Root Cert on `cloud.server.acme`:
  - `/var/lib/nextcloud/ca-certificates/step-ca.crt`
- Ensure Nextcloud certs and root CA are readable by Nextcloud (UID/GID 33)
- Uncomment certificate volumes in Nextcloud `docker-compose.yml.j2`

- Restart Keycloak and Nextcloud containers

**Ansible Vault & Deployment**
- Encrypt the secrets file: `ansible-vault encrypt ansible/group_vars/all/vault.yml`
- Deploy Keycloak: `ansible-playbook -i production keycloak.yml --ask-vault-pass`
- Deploy Nextcloud: `ansible-playbook -i production nextcloud.yml --ask-vault-pass`

