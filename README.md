# acme-infrastructure

On MacOS, use [Homebrew](https://brew.sh/).

Install [Vagrant](https://developer.hashicorp.com/vagrant/install).

```bash
brew tap hashicorp/tap
brew install hashicorp/tap/hashicorp-vagrant
```

Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads). If you have M-series MacBook, use `macOS / Apple Silicon hosts`.

Recommendation: install [direnv](https://direnv.net/), also [hook to your shell](https://direnv.net/docs/hook.html).

Go to `vagrant` directory and add the birdge interface to `.envrc`, you can copy `.envrc.example`

```bash
cd vagrant
cp .envrc.example .envrc # make sure you have direnv installed
# modify .envrc with correct bridge ifs
direnv allow .
```

Then start the VMs.

```bash
vagrant up
```

Run setup script to get SSH config for ansible.

```bash
./setup.sh
```

To ansible, make sure you have venv.

```bash
cd ..
cd ansible
direnv allow . # this will create a new .venv
```

Run playbooks

```bash
ansible-playbook dns.yml
```
