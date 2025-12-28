# OTF — OpenTofu/Terraform wrapper with encrypted state/vars

`otf` is a small CLI wrapper that decrypts selected OpenTofu/Terraform files before running a command, then re-encrypts them afterward. This keeps state/vars encrypted at rest while preserving a normal workflow.

Repository URL: https://github.com/HrBingR/otf_script

## What it does

- Decrypts target files in-place
- Runs OpenTofu (`tofu`) or Terraform (`terraform`)
- Re-encrypts the target files in-place
- Exits with the same status code as the underlying command

## Requirements

- Python 3 (installed automatically inside pipx’s isolated env)
- OpenTofu (`tofu`) or Terraform (`terraform`) available on `PATH`

## Install (recommended: pipx)

Install from this repo:

```shell
pipx install "git+https://github.com/HrBingR/otf_script.git"
```

Install updates:

```shell
pipx upgrade otf
```

Uninstall:

```shell
pipx uninstall otf
```

## Configuration

`otf` reads configuration from environment variables and will also 
load a local `.env` file from the current working directory.

Required:

- OTF_PASSWORD: password used to derive the encryption key.

Optional:

- OTF_COMMAND: `tofu` (default) or `terraform`
- TARGET_FILES: comma-separated list of files to encrypt/decrypt  
  Default: `terraform.tfvars, terraform.tfstate, terraform.tfstate.backup`

Example `.env`:

    OTF_PASSWORD=<YOUR_PASSWORD>
    OTF_COMMAND=tofu
    TARGET_FILES=terraform.tfvars,terraform.tfstate,terraform.tfstate.backup

## Usage

Show help / usage:

    otf

Decrypt only (for manual editing/inspection):

    otf -d

Encrypt only (after editing):

    otf -e

Show encryption status for target files:

    otf -s

Normal wrapper flow (decrypt → run → encrypt):

    otf init
    otf plan
    otf apply
    otf destroy

Pass through any arguments you’d normally give to OpenTofu/Terraform:

    otf init -upgrade
    otf apply -auto-approve

## Notes / safety

- This tool encrypts and decrypts files in-place. If you decrypt, plaintext will exist on disk until you re-encrypt.
- Treat `OTF_PASSWORD` like a secret. Don’t commit it. Prefer a secret manager or a securely managed `.env`.
- Target files should exist; missing files may cause errors depending on your workflow.

## Suggested .gitignore entries

At minimum:

```shell
.env
```
