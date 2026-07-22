---
title: Installation
order: 2
docs: true
install: true
relationships:
  references: linux-user-service
---

Wyrwood currently supports Linux on `amd64` and `arm64`. Install a package from
the Wyrd repository, use the Arch User Repository (AUR), or download a release
archive.

## APT

Add the Wyrd package signing key and repository, then install Wyrwood:

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

## RPM

Add the Wyrd repository definition and install with DNF:

```bash
sudo curl -fsSL https://repo.wyrd.foo/wyrd.repo \
  -o /etc/yum.repos.d/wyrd.repo
sudo dnf install wyrwood
```

## Arch User Repository

The prebuilt AUR package is `wyrwood-bin`. Install it with an AUR helper, for
example:

```bash
paru -S wyrwood-bin
```

## Release archive

Each [GitHub release](https://github.com/wyrd-company/wyrwood/releases)
provides Linux `tar.gz`, DEB, and RPM artifacts for `amd64` and `arm64`, plus a
`checksums.txt` file. Verify the archive, extract `wyrwood`, and place it on your
`PATH`.

```bash
archive=wyrwood_RELEASE_linux_x86_64.tar.gz
sha256sum --check checksums.txt --ignore-missing
tar -xzf "$archive"
sudo install -m 0755 wyrwood /usr/local/bin/wyrwood
```

Replace `RELEASE` with the selected version and `x86_64` with `aarch64` for a
Linux arm64 host.

## Build from source

Building requires the Go version declared in the repository's `go.mod` file.

```bash
git clone https://github.com/wyrd-company/wyrwood.git
cd wyrwood
go build -o wyrwood ./cmd/wyrwood
sudo install -m 0755 wyrwood /usr/local/bin/wyrwood
```

## Verify

```bash
wyrwood version
wyrwood help
```

After an upgrade, restart an active daemon so it runs the new executable:

```bash
wyrwood service stop
wyrwood service start
```

Consumer sockets are unavailable between those commands.
