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

The controller is published as a container image. It needs a dedicated
OpenBao namespace, an AppRole in that namespace, an OpenID Connect client for
operator sign-in, a state volume, and a configuration file. The AppRole
secret identifier and the client secret are read from mounted files.

### OpenBao

Create the namespace and its mounts with an OpenBao administrator token.
[Policies and contracts](configuration.md#openbao-namespace) explains why the
namespace is required and gives the controller policy; save it as
`controller.hcl`.

```bash
bao namespace create wyrwood
export BAO_NAMESPACE=wyrwood
bao auth enable approle
bao secrets enable -version=2 kv
bao secrets enable transit
bao secrets enable ssh
bao write ssh/config/ca generate_signing_key=true key_type=ed25519
bao policy write controller controller.hcl
bao write auth/approle/role/controller token_policies=controller token_ttl=1h
bao read -field=role_id auth/approle/role/controller/role-id
bao write -f -field=secret_id auth/approle/role/controller/secret-id
```

Keep the secrets your containers read in this namespace.

### Controller container

The image runs as user and group 65532. State lives in a named volume, which
Docker creates with that ownership from the image. The two secret files must
be readable by that user.

In your identity provider, for example Pocket ID, create a confidential
client with PKCE, set its redirect URL to
`https://<controller public host>/auth/callback`, and create the group whose
members may operate Wyrwood.

```bash
mkdir -p ~/wyrwood
# Paste each secret when prompted, then press Ctrl-D.
cat > ~/wyrwood/secret-id
cat > ~/wyrwood/oidc-client-secret
sudo chown 65532:65532 ~/wyrwood/secret-id ~/wyrwood/oidc-client-secret
sudo chmod 0400 ~/wyrwood/secret-id ~/wyrwood/oidc-client-secret

cat > ~/wyrwood/controller.yml <<'YAML'
http:
  # Inside the container; the published port below keeps it on host loopback.
  listen: 0.0.0.0:8080
ssh:
  listen: 0.0.0.0:2222
openbao:
  address: https://openbao.example.internal:8200
  namespace: wyrwood
  approle:
    role-id: REPLACE_WITH_ROLE_ID
    secret-id-file: /run/secrets/openbao-secret-id
oidc:
  provider-name: Pocket ID
  issuer: https://id.example.internal
  client-id: REPLACE_WITH_CLIENT_ID
  client-secret-file: /run/secrets/oidc-client-secret
  redirect-url: https://wyrwood.example.internal/auth/callback
  allowed-groups:
    - wyrwood-operators
YAML

docker run -d --name wyrwood-controller \
  -p 127.0.0.1:8080:8080 -p 2222:2222 \
  -v wyrwood-state:/var/lib/wyrwood \
  -v ~/wyrwood/controller.yml:/etc/wyrwood/controller.yml:ro \
  -v ~/wyrwood/secret-id:/run/secrets/openbao-secret-id:ro \
  -v ~/wyrwood/oidc-client-secret:/run/secrets/oidc-client-secret:ro \
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
unit. Packages do not start the agent before enrollment.

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

### Configure the access group

An access group is effectively required for non-root containers running as a
UID other than the agent user. Without it, the consumer directory is `0700`
and sockets are `0600`, owned by the agent user; with it, they are `0750` and
`0660`. Set the policy's numeric access group to a host GID held by the
container processes.

Packages add the agent user to `docker` only. Add `wyrwood` to each access
group on the host. For example, for access group 1000:

```bash
getent group 1000
sudo usermod -aG <host-group-name> wyrwood
```

Replace `<host-group-name>` with the host group name for GID 1000. Create a
host group with that GID first if needed. Start the agent after enrollment if
it is not running yet. Restart a running agent so it gets the new membership:

```bash
sudo systemctl restart wyrwood-agent
```

Members of this host group who can reach the sockets can use the binding's
OpenBao and SSH permissions. See [Access group](configuration.md#access-group).

### Start the agent

After [enrolling the agent](getting-started.md#enroll-the-agent), start it:

```bash
sudo wyrwood agent service start
```

This starts the agent immediately and enables it to start at boot for both
package and release archive installations. `sudo wyrwood agent service stop`
stops the agent without disabling startup at boot. To disable startup at
boot, run `sudo systemctl disable wyrwood-agent`.

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
