#!/usr/bin/env python3
"""
OpenTofu wrapper script with Ansible Vault encryption/decryption.
"""
from __future__ import annotations
import os
import sys
import subprocess
import base64

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dataclasses import dataclass
from typing import Final, Callable, Protocol


# Files to encrypt/decrypt
encryption_version = 1
V1_FIXED_HEADER_SIZE_WITHOUT_SALT: Final[int] = (
    4  # magic
    + 2  # version
    + 2  # header_len field itself
    + 2  # kdf_id
    + 2  # kdf_len
    + 4  # kdf_iters
    + 2  # salt_len
)
MAGIC_PREFIX: Final[bytes] = b"OTFM"


@dataclass(frozen=True, slots=True)
class FormatConfig:
    version: int
    salt_len: int
    kdf_id: int
    kdf_len: int
    kdf_iters: int

    def header_len(self) -> int:
        if self.version != 1:
            raise ValueError(f"Unsupported format version for header sizing: {self.version}")
        return V1_FIXED_HEADER_SIZE_WITHOUT_SALT + self.salt_len


class DerivingKDF(Protocol):
    def derive(self, key_material: bytes) -> bytes: ...


KDF_BUILDER_BY_ID: Final[dict[int, Callable[[int, bytes, int], DerivingKDF]]] = {
    1: lambda length, salt, iters: PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iters,
    ),
}


FORMAT_BY_VERSION: Final[dict[int, FormatConfig]] = {
    1: FormatConfig(
        version=1,
        salt_len=16,
        kdf_id=1,
        kdf_len=32,
        kdf_iters=1_200_000,
    ),
}


def build_v1_header(cfg: FormatConfig, *, salt: bytes) -> bytes:
    if cfg.version != 1:
        raise ValueError("build_v1_header only supports version 1")
    if len(salt) != cfg.salt_len:
        raise ValueError(f"Salt length mismatch: expected {cfg.salt_len}, got {len(salt)}")

    header_len = cfg.header_len()

    return (
        MAGIC_PREFIX
        + cfg.version.to_bytes(2, "big")
        + header_len.to_bytes(2, "big")
        + cfg.kdf_id.to_bytes(2, "big")
        + cfg.kdf_len.to_bytes(2, "big")
        + cfg.kdf_iters.to_bytes(4, "big")
        + cfg.salt_len.to_bytes(2, "big")
        + salt
    )


@dataclass(frozen=True, slots=True)
class ParsedHeaderV1:
    version: int
    header_len: int
    kdf_id: int
    kdf_len: int
    kdf_iters: int
    salt_len: int
    salt: bytes
    ciphertext: bytes


def parse_v1_header(data: bytes) -> ParsedHeaderV1:
    """
    Parse v1 header from a full file payload (header + ciphertext).
    Layout:
      magic(4) | version(2) | header_len(2) | kdf_id(2) | kdf_len(2) | kdf_iters(4) | salt_len(2) | salt | ciphertext
    """
    min_len = V1_FIXED_HEADER_SIZE_WITHOUT_SALT
    if len(data) < min_len:
        raise ValueError(f"File too small to be OTF v1 (need >= {min_len} bytes, got {len(data)})")

    if data[:4] != MAGIC_PREFIX:
        raise ValueError("Bad magic prefix")

    version = int.from_bytes(data[4:6], "big")
    if version != 1:
        raise ValueError(f"parse_v1_header called for non-v1 file (version={version})")

    header_len = int.from_bytes(data[6:8], "big")
    kdf_id = int.from_bytes(data[8:10], "big")
    kdf_len = int.from_bytes(data[10:12], "big")
    kdf_iters = int.from_bytes(data[12:16], "big")
    salt_len = int.from_bytes(data[16:18], "big")

    expected_header_len = V1_FIXED_HEADER_SIZE_WITHOUT_SALT + salt_len
    if header_len != expected_header_len:
        raise ValueError(f"Header length mismatch: header says {header_len}, expected {expected_header_len}")

    if len(data) < header_len:
        raise ValueError(f"Truncated file: header_len={header_len}, file_len={len(data)}")

    salt = data[18:18 + salt_len]
    if len(salt) != salt_len:
        raise ValueError("Truncated salt")

    ciphertext = data[header_len:]
    if not ciphertext:
        raise ValueError("Missing ciphertext payload")

    return ParsedHeaderV1(
        version=version,
        header_len=header_len,
        kdf_id=kdf_id,
        kdf_len=kdf_len,
        kdf_iters=kdf_iters,
        salt_len=salt_len,
        salt=salt,
        ciphertext=ciphertext,
    )


def parse_otf_header(data: bytes) -> ParsedHeaderV1:
    """
    Dispatcher for parsing OTF-encrypted payloads.
    Currently supports v1 only.
    """
    if len(data) < 6:
        raise ValueError("File too small to contain OTF header")

    if data[:4] != MAGIC_PREFIX:
        raise ValueError("Not an OTF file (bad magic)")

    version = int.from_bytes(data[4:6], "big")
    if version == 1:
        return parse_v1_header(data)

    raise ValueError(f"Unsupported OTF format version: {version}")


def atomic_write_bytes(target_path: str, data: bytes) -> None:
    """
    Atomically replace target_path with data.

    Linux/POSIX strategy:
      - write to temp file in same directory
      - fsync temp file
      - os.replace(temp, target)
      - fsync directory (durable rename)
    """
    dir_path = os.path.dirname(target_path) or "."
    base_name = os.path.basename(target_path)
    tmp_path = os.path.join(dir_path, f".{base_name}.tmp")

    try:
        st_mode = os.stat(target_path).st_mode & 0o777
    except FileNotFoundError:
        st_mode = 0o600

    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, st_mode)
    try:
        with os.fdopen(fd, "wb") as f_out:
            f_out.write(data)
            f_out.flush()
            os.fsync(f_out.fileno())

        os.replace(tmp_path, target_path)

        dir_fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def check_encryption(data):
    if data[:4] == MAGIC_PREFIX:
        return True
    return False

def decrypt_files(password, target_files):
    """
    Decrypt sensitive files.
    """
    print("\n=== Decrypting files ===")
    for file in target_files:
        with open(file, "rb") as f_in:
            data = f_in.read()
        is_encrypted = check_encryption(data)
        if not is_encrypted:
            print(f"WARNING: Skipping non-OTF/non-encrypted file: {file}", file=sys.stderr)
            continue
        try:
            hdr = parse_otf_header(data)
        except ValueError as e:
            print(f"ERROR: Cannot parse header for {file}: {e}", file=sys.stderr)
            continue
        try:
            kdf_builder = KDF_BUILDER_BY_ID[hdr.kdf_id]
        except KeyError:
            print(f"ERROR: Unsupported kdf_id {hdr.kdf_id} in file {file}", file=sys.stderr)
            continue
        kdf = kdf_builder(hdr.kdf_len, hdr.salt, hdr.kdf_iters)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        try:
            decrypted_data = f.decrypt(hdr.ciphertext)
        except InvalidToken:
            print(f"ERROR: Invalid password or corrupted file: {file}", file=sys.stderr)
            continue
        atomic_write_bytes(file, decrypted_data)


def encrypt_files(password, target_files):
    """
    Encrypt sensitive files.
    """
    print("\n=== Encrypting files ===")
    for file in target_files:
        encryption_config = FORMAT_BY_VERSION[encryption_version]
        salt = os.urandom(encryption_config.salt_len)
        kdf = KDF_BUILDER_BY_ID[encryption_config.kdf_id](encryption_config.kdf_len, salt, encryption_config.kdf_iters)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        with open(file, "rb") as f_in:
            data = f_in.read()
        is_encrypted = check_encryption(data)
        if is_encrypted:
            print(f"WARNING: Skipping already encrypted file: {file}", file=sys.stderr)
            continue
        encrypted_data = f.encrypt(data)
        header = build_v1_header(encryption_config, salt=salt)
        out_bytes = header + encrypted_data
        atomic_write_bytes(file, out_bytes)


def init() -> tuple[bytes, list[str], list[str]]:
    """
    Checks if OTF_PASSWORD env is defined
    """
    load_dotenv()
    otf_pass = os.getenv("OTF_PASSWORD")
    if not otf_pass:
        print("ERROR: OTF_PASSWORD environment variable not found", file=sys.stderr)
        sys.exit(1)
    otf_pass = otf_pass.encode("utf-8")
    raw = os.getenv("TARGET_FILES")
    if not raw:
        target_files = ["terraform.tfvars", "terraform.tfstate", "terraform.tfstate.backup"]
    else:
        target_files = [part.strip() for part in raw.split(",") if part.strip()]
    command = os.getenv("OTF_COMMAND")
    if not command:
        command = "tofu"
    if command not in ["tofu", "terraform"]:
        print(
            f"ERROR: Unsupported OTF_COMMAND: {command}. Supported commands are 'tofu' and 'terraform'",
            file=sys.stderr
        )
        sys.exit(1)
    command = [command]
    return otf_pass, target_files, command


def main():
    encryption_password, target_files, command = init()
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        decrypt_files(encryption_password, target_files)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "-e":
        encrypt_files(encryption_password, target_files)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "-s":
        encrypted_files = []
        for file in target_files:
            with open(file, "rb") as f_in:
                data = f_in.read(4)
            is_encrypted = check_encryption(data)
            status = "encrypted" if is_encrypted else "unencrypted"
            encrypted_files.append(f"{file}: {status}")
        print("\n".join(encrypted_files), file=sys.stdout)
        sys.exit(0)
    if len(sys.argv) > 1:
        tofu_arg = sys.argv[1:]
    else:
        print(f"""
        Usage:
          otf.py [-d | -e | -s] [tofu/terraform args...]

        Description:
          This script is a small wrapper around OpenTofu/Terraform that keeps your
          Terraform state and variables encrypted at rest.

        Modes:
          -d    Decrypt target files in-place, then exit.
                Use this before manually editing terraform.tfvars or inspecting state.

          -e    Encrypt target files in-place, then exit.
                Use this after editing/running tools so the files are safe to store in VCS.

          -s    Show encryption status for each target file, then exit.
                Reports "encrypted" when the file starts with the OTF magic header.

        Standard flow:
          1) Decrypt target files in-place
          2) Run OpenTofu/Terraform with specified arguments
          3) Re-encrypt target files in-place
          4) Exit with the same status code as the tofu/terraform command

        Examples:
          Print this output:
            ./otf.py

          Apply changes:
            ./otf.py apply
            
          Init upgrade:
            ./otf.py init -upgrade

          Decrypt files for manual editing:
            ./otf.py -d

          Re-encrypt files after editing:
            ./otf.py -e

          Check which files are encrypted:
            ./otf.py -s

        Environment:
          OTF_PASSWORD   Required. Password used to derive the encryption key.
          OTF_COMMAND    Optional. Either "tofu" (default) or "terraform".
          TARGET_FILES   Optional. Comma-separated list of files to encrypt/decrypt.
                        Default: terraform.tfvars, terraform.tfstate, terraform.tfstate.backup

        Notes:
          - This tool overwrites files in-place. If you decrypt (-d), plaintext files will exist
            on disk until you re-encrypt (-e) or run the default flow.
          - Target files must exist, otherwise the script may error.
        """, file=sys.stdout)
        sys.exit(0)

    decrypt_files(encryption_password, target_files)
    print(f"\n=== Running {command} {tofu_arg} ===")
    for arg in tofu_arg:
        command.append(arg)
    result = subprocess.run(command)
    tofu_exit_code = result.returncode
    encrypt_files(encryption_password, target_files)

    # Exit with the same code as tofu command
    sys.exit(tofu_exit_code)


if __name__ == "__main__":
    main()