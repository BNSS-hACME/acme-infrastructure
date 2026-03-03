# acme-infrastructure

Infrastructure-as-code for an academic network security lab. Provisions a set of VMs and physical Raspberry Pi devices that together simulate a corporate network with PKI, identity management, VPN, DNS, cloud storage, and secure web services.

## Overview

This project is part of a course on network security and implements a full IAM and PKI stack using open-source tools: [Step CA](https://smallstep.com/docs/step-ca/) for certificate management, [Keycloak](https://www.keycloak.org/) for OIDC identity, and [FreeRADIUS](https://freeradius.org/) for network authentication. Supporting services include OpenVPN, Nextcloud, an Apache HTTPS front-end, and an AI service — all running as VMs provisioned by Vagrant and configured by Ansible. Two Raspberry Pis provide physical WAN/LAN routing at each deployment site.

## Architecture

### Network Layout

```
Internet / ISP
      |
  [eth0 DHCP]
  Raspberry Pi          ← physical device, one per site (stockholm / london)
  [eth1 192.168.50.1]
      |   192.168.50.0/24
  Physical Router       ← gets address via RPi DHCP (192.168.50.x)
      |   10.0.10.0/24  (physical LAN)
  router.server.acme    ← VM bridged to physical LAN (10.0.10.50)
      |   10.0.50.0/24  (internal VM network)
  ┌───┴────────────────────────────────────┐
  dns  vpn  auth  cloud  ai  secure  dvwa
```

Both sites share the same physical LAN subnet (`10.0.10.0/24`) and internal VM subnet (`10.0.50.0/24`). The Raspberry Pi at each site acts as a WAN/LAN pass-through router with NAT, placing the physical router (and in turn all VMs) behind it.

### Virtual Machines

| Service               | Host               | IP                     | Description                               |
| --------------------- | ------------------ | ---------------------- | ----------------------------------------- |
| Router                | router.server.acme | 10.0.10.50 / 10.0.50.1 | NAT gateway, bridges physical and VM LANs |
| DNS                   | dns.server.acme    | 10.0.50.10             | Unbound DNS resolver                      |
| Certificate Authority | auth.server.acme   | 10.0.50.13             | Step CA, Keycloak OIDC, FreeRADIUS        |
| VPN                   | vpn.server.acme    | 10.0.50.11             | OpenVPN server                            |
| Cloud Storage         | cloud.server.acme  | 10.0.50.12             | Nextcloud with OIDC integration           |
| Secure Web            | secure.server.acme | 10.0.50.20             | Apache HTTPS with OpenIDC authentication  |
| AI                    | ai.server.acme     | 10.0.50.14             | AI service deployment                     |
| DVWA                  | dvwa.server.acme   | 10.0.50.50             | Damn Vulnerable Web App (lab environment) |

### Physical Devices

| Device | Host             | LAN IP       | Description                                              |
| ------ | ---------------- | ------------ | -------------------------------------------------------- |
| RPi 1  | rpi1.server.acme | 192.168.50.1 | WAN/LAN router in front of the stockholm physical router |
| RPi 2  | rpi2.server.acme | 192.168.50.1 | WAN/LAN router in front of the london physical router    |

The RPis are reachable for Ansible management via dynamic DNS (`rpi1-hacme.mooo.com`, `rpi2-hacme.mooo.com`). Each Pi bridges its WAN interface (`eth0`, DHCP from ISP) to a LAN interface (`eth1`, static `192.168.50.1/24`) and runs a DHCP server for the downstream physical router.

## Prerequisites

On macOS, use [Homebrew](https://brew.sh/).

**For VM provisioning:**

- [Vagrant](https://developer.hashicorp.com/vagrant/install)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) — if you have an M-series MacBook, use `macOS / Apple Silicon hosts`
- [direnv](https://direnv.net/) (recommended) — also [hook it to your shell](https://direnv.net/docs/hook.html)

```bash
brew tap hashicorp/tap
brew install hashicorp/tap/hashicorp-vagrant
```

**For Ansible (VM and RPi configuration):**

- Python 3 with `pip`
- Ansible (installed automatically via the `ansible/` direnv)

```bash
brew install python direnv
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
