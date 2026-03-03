# acme-infrastructure

[Short description of the project — what it is, what it does, and why it exists]

## Overview

[High-level summary: academic project, federated PKI, IAM, secure services, etc.]

## Architecture

[Diagram or description of the network topology]

### Network Layout

[The two networks: 10.0.50.0/24 internal, 10.0.10.0/24 external, subnets]

### Services

| Service               | Host               | IP                     | Description                               |
| --------------------- | ------------------ | ---------------------- | ----------------------------------------- |
| Router                | router.server.acme | 10.0.50.1 / 10.0.10.50 | NAT gateway, network bridge               |
| DNS                   | dns.server.acme    | 10.0.50.10             | Unbound DNS resolver                      |
| Certificate Authority | auth.server.acme   | 10.0.50.13             | Step CA, Keycloak OIDC, FreeRADIUS        |
| VPN                   | vpn.server.acme    | 10.0.50.11             | OpenVPN server                            |
| Cloud Storage         | cloud.server.acme  | 10.0.50.12             | Nextcloud with OIDC integration           |
| Secure Web            | secure.server.acme | 10.0.50.20             | Apache HTTPS with OpenIDC authentication  |
| AI                    | ai.server.acme     | 10.0.50.14             | AI service deployment                     |
| DVWA                  | dvwa.server.acme   | 10.0.50.50             | Damn Vulnerable Web App (lab environment) |

## Prerequisites

[Tools needed and version requirements]

On MacOS, use [Homebrew](https://brew.sh/).

- [Vagrant](https://developer.hashicorp.com/vagrant/install)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) — if you have an M-series MacBook, use `macOS / Apple Silicon hosts`
- [direnv](https://direnv.net/) (recommended) — also [hook it to your shell](https://direnv.net/docs/hook.html)

```bash
brew tap hashicorp/tap
brew install hashicorp/tap/hashicorp-vagrant
```

## Getting Started

### 1. Set up Virtual Machines (Vagrant)

Go to the `vagrant` directory and configure the bridge interface. You can copy the example env file:

```bash
cd vagrant
cp .envrc.example .envrc
# Modify .envrc with the correct bridge interface
direnv allow .
```

Then start the VMs:

```bash
vagrant up
```

Run the setup script to generate the SSH config for Ansible:

```bash
./setup.sh
```

### 2. Configure Ansible

Make sure you have a virtual environment set up:

```bash
cd ../ansible
direnv allow . # This will create a new .venv
```

### 3. Run Playbooks

Run individual playbooks as needed:

```bash
ansible-playbook dns.yml
```

Or run the full stack with the master playbook:

```bash
ansible-playbook all.yml
```

## Project Structure

```
acme-infrastructure/
├── ansible/      # Playbooks and roles for all services
├── vagrant/      # VM definitions and provisioning
├── scripts/      # Utility scripts
└── docs/         # Additional documentation
```

## Configuration

[Where to find and how to configure host variables, vault secrets, `.envrc`, etc.]

## References

[Links to related work, papers, and tools — e.g., NSS-VPKI, Step CA, Keycloak]

## License

[License info]
