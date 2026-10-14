---
title: Installation
order: 2
docs: true
install: true
relationships:
  references:
    - linux-service
---

Install the controller once per site and the agent on every host that runs
containers.

## Controller

The controller is published as a container image. It needs an OpenBao
AppRole whose policy covers the Wyrwood prefix, a state volume, and a
configuration file. The secret identifier is read from a mounted file.

```bash
mkdir -p ~/wyrwood/state
cat > ~/wyrwood/controller.yml <<'YAML'
http:
  listen: 127.0.0.1:8080
ssh:
  listen: 0.0.0.0:2222
openbao:
  address: https://openbao.example.internal:8200
  approle:
    role-id: REPLACE_WITH_ROLE_ID
    secret-id-file: /run/secrets/openbao-secret-id
YAML

docker run -d --name wyrwood-controller \
  -p 127.0.0.1:8080:8080 -p 2222:2222 \
  -v ~/wyrwood/state:/var/lib/wyrwood \
  -v ~/wyrwood/controller.yml:/etc/wyrwood/controller.yml:ro \
  -v ~/wyrwood/secret-id:/run/secrets/openbao-secret-id:ro \
  ghcr.io/wyrd-company/wyrwood:latest
```

Print the controller's SSH host-key fingerprint so you can compare it when
an agent logs in:

```bash
docker exec wyrwood-controller wyrwood controller host-key
```

## Agent

The agent supports Linux on `amd64` and `arm64`. Install a package from the
Wyrd repository or the Arch User Repository (AUR). Packages create the
`wyrwood` system user, add it to the `docker` group, and install the system
unit.

### APT

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://repo.wyrd.foo/pubkey.gpg |
  sudo tee /etc/apt/keyrings/wyrd-company.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/wyrd-company.gpg] \
https://repo.wyrd.foo/apt stable main" |
  sudo tee /etc/apt/sources.list.d/wyrd-company.list >/dev/null
sudo apt update
sudo apt install wyrwood
```

### RPM

```bash
sudo curl -fsSL https://repo.wyrd.foo/wyrd.repo \
  -o /etc/yum.repos.d/wyrd.repo
sudo dnf install wyrwood
```

### Arch User Repository

```bash
paru -S wyrwood-bin
```

### Release archive

Each [GitHub release](https://github.com/wyrd-company/wyrwood/releases)
provides Linux `tar.gz`, DEB, and RPM artifacts for `amd64` and `arm64`, plus
`checksums.txt`. After extracting the executable, create the service user and
unit yourself:

```bash
sudo install -m 0755 wyrwood /usr/local/bin/wyrwood
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --groups docker wyrwood
sudo wyrwood agent service install
```

## Verify

```bash
wyrwood version
```

After upgrading the agent, restart it so it runs the new executable:

```bash
sudo systemctl restart wyrwood-agent
```

Consumer sockets are restored from cached policy before the agent contacts
the controller, so bound containers keep their endpoints across the restart.
