#!/usr/bin/env python3
"""Interactive bootstrap for a Borg server user and SSH access."""

from __future__ import annotations

import getpass
import grp
import os
import pwd
import secrets
import shlex
import shutil
import socket
import string
import subprocess
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography.utils import CryptographyDeprecationWarning
except ImportError:
    CryptographyDeprecationWarning = None

if CryptographyDeprecationWarning is not None:
    warnings.filterwarnings(
        "ignore",
        category=CryptographyDeprecationWarning,
        module=r"paramiko\..*",
    )

try:
    import paramiko
except ImportError:
    paramiko = None


SSH_PORT = 22
SOCKET_TIMEOUT_SECONDS = 5
COMMAND_TIMEOUT_SECONDS = 30
KEY_TYPE = "ed25519"
KEY_NAME = "id_ed25519"


@dataclass(frozen=True)
class TargetKeyInfo:
    private_key_path: str
    public_key_path: str
    public_key: str
    status: str


@dataclass(frozen=True)
class BorgUserInfo:
    username: str
    home: Path
    password: str | None
    created: bool


def fail(message: str, exit_code: int = 1) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def require_root() -> None:
    if not hasattr(os, "geteuid"):
        fail("This script must be run on a POSIX/Linux Borg server.")
    if os.geteuid() != 0:
        fail("This script must be run as root on the Borg server.")


def require_paramiko() -> None:
    if paramiko is None:
        fail(
            "Python package 'paramiko' is required. Install it with: "
            "apt install -y python3-paramiko"
        )


def prompt_required(prompt: str) -> str:
    value = input(prompt).strip()
    if not value:
        fail("Empty value is not allowed.")
    return value


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def prompt_borg_address() -> str:
    detected = detect_fqdn()
    if detected:
        value = input(f"Borg server address [{detected}]: ").strip()
        return value or detected
    return prompt_required("Borg server address: ")


def detect_fqdn() -> str:
    try:
        result = subprocess.run(
            ["hostname", "-f"],
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def validate_domain_as_username(domain: str) -> None:
    if "/" in domain or ":" in domain or domain.startswith("-") or domain in {".", ".."}:
        fail("Domain cannot be safely used as a Linux username.")
    if len(domain) > 32:
        print(
            "WARNING: username is longer than 32 characters; make sure your Linux "
            "distribution supports it."
        )


def resolve_host(host: str) -> list[str]:
    print(f"Checking DNS for {host}...")
    try:
        infos = socket.getaddrinfo(host, SSH_PORT, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        fail(f"DNS resolution failed for {host}: {exc}")

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        fail(f"DNS resolution returned no addresses for {host}.")
    print(f"Resolved {host}: {', '.join(addresses)}")
    return addresses


def check_tcp_port(host: str, port: int = SSH_PORT) -> None:
    print(f"Checking TCP/{port} on {host}...")
    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS):
            pass
    except OSError as exc:
        fail(f"TCP/{port} is not reachable on {host}: {exc}")
    print(f"TCP/{port} is reachable.")


def connect_target(host: str, username: str, password: str) -> "paramiko.SSHClient":
    require_paramiko()
    print(f"Checking SSH password login to {username}@{host}...")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=SSH_PORT,
            username=username,
            password=password,
            timeout=SOCKET_TIMEOUT_SECONDS,
            auth_timeout=SOCKET_TIMEOUT_SECONDS,
            banner_timeout=SOCKET_TIMEOUT_SECONDS,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as exc:
        client.close()
        fail(f"SSH password login failed for {username}@{host}: {exc}")
    print("SSH password login works.")
    return client


def run_remote(client: "paramiko.SSHClient", command: str, timeout: int = COMMAND_TIMEOUT_SECONDS) -> str:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.close()
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if exit_code != 0:
        details = err.strip() or out.strip() or f"exit code {exit_code}"
        raise RuntimeError(f"Remote command failed: {command}\n{details}")
    return out


def run_local(command: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )


def scan_ssh_host_keys(host: str) -> list[str]:
    ssh_keyscan = shutil.which("ssh-keyscan")
    if not ssh_keyscan:
        fail("ssh-keyscan is required on the Borg server. Install it with: apt install -y openssh-client")

    result = run_local([ssh_keyscan, "-T", str(SOCKET_TIMEOUT_SECONDS), host])
    if result.returncode != 0 or not result.stdout.strip():
        fail(f"Could not scan SSH host key for {host}: {result.stderr.strip()}")

    return [line for line in result.stdout.splitlines() if line and not line.startswith("#")]


def user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(username)
    except KeyError:
        return False
    return True


def generate_password(length: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits + "_%@+=,.-"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def set_user_password(username: str) -> str:
    password = generate_password()
    result = run_local(["chpasswd"], input_text=f"{username}:{password}\n")
    if result.returncode != 0:
        fail(f"chpasswd failed: {result.stderr.strip() or result.stdout.strip()}")
    return password


def create_borg_user(username: str) -> BorgUserInfo:
    home = Path("/home") / username
    if user_exists(username):
        if not prompt_yes_no(
            f"Borg user '{username}' already exists. Continue without changing it?",
            default=False,
        ):
            fail(f"Borg user '{username}' already exists. No changes were made.")
        password = None
        if prompt_yes_no(
            f"Generate and set a new password for existing Borg user '{username}'?",
            default=False,
        ):
            password = set_user_password(username)
        return BorgUserInfo(username=username, home=home, password=password, created=False)

    print(f"Creating Borg user {username}...")
    result = run_local(["useradd", "-m", "-s", "/bin/bash", username])
    if result.returncode != 0:
        fail(f"useradd failed: {result.stderr.strip() or result.stdout.strip()}")

    password = set_user_password(username)
    return BorgUserInfo(username=username, home=home, password=password, created=True)


def ensure_borg_ssh_files(user_info: BorgUserInfo) -> Path:
    account = pwd.getpwnam(user_info.username)
    group = grp.getgrgid(account.pw_gid)
    home = user_info.home
    ssh_dir = home / ".ssh"
    authorized_keys = ssh_dir / "authorized_keys"

    print(f"Preparing {ssh_dir}...")
    home.mkdir(mode=0o755, parents=True, exist_ok=True)
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    authorized_keys.touch(mode=0o600, exist_ok=True)

    os.chown(home, account.pw_uid, group.gr_gid)
    os.chown(ssh_dir, account.pw_uid, group.gr_gid)
    os.chown(authorized_keys, account.pw_uid, group.gr_gid)
    ssh_dir.chmod(0o700)
    authorized_keys.chmod(0o600)
    return authorized_keys


def append_authorized_key(authorized_keys: Path, public_key: str) -> bool:
    normalized_key = public_key.strip()
    existing = authorized_keys.read_text(encoding="utf-8", errors="replace").splitlines()
    if normalized_key in {line.strip() for line in existing if line.strip()}:
        print("Target public key is already present in authorized_keys.")
        return False

    print(f"Adding target public key to {authorized_keys}...")
    with authorized_keys.open("a", encoding="utf-8") as file:
        if existing and existing[-1].strip():
            file.write("\n")
        file.write(normalized_key + "\n")
    return True


def ensure_local_known_host(host: str) -> None:
    ssh_keygen = shutil.which("ssh-keygen")

    known_hosts = Path("/root/.ssh/known_hosts")
    known_hosts.parent.mkdir(mode=0o700, exist_ok=True)
    known_hosts.touch(mode=0o600, exist_ok=True)
    known_hosts.parent.chmod(0o700)
    known_hosts.chmod(0o600)

    if ssh_keygen:
        check = run_local([ssh_keygen, "-F", host, "-f", str(known_hosts)])
        if check.returncode == 0 and check.stdout.strip():
            return

    existing = known_hosts.read_text(encoding="utf-8", errors="replace")
    new_lines = [line for line in scan_ssh_host_keys(host) if line not in existing]
    if not new_lines:
        return
    with known_hosts.open("a", encoding="utf-8") as file:
        if existing and not existing.endswith("\n"):
            file.write("\n")
        file.write("\n".join(new_lines) + "\n")


def get_target_home(client: "paramiko.SSHClient") -> str:
    home = run_remote(client, "printf '%s\\n' \"$HOME\"").strip()
    if not home.startswith("/"):
        fail(f"Could not determine target user home directory, got: {home!r}")
    return home


def ensure_target_key(client: "paramiko.SSHClient") -> TargetKeyInfo:
    home = get_target_home(client)
    ssh_dir = f"{home}/.ssh"
    private_key = f"{ssh_dir}/{KEY_NAME}"
    public_key = f"{private_key}.pub"

    print(f"Preparing target SSH key at {private_key}...")
    quoted_private_key = shlex.quote(private_key)
    quoted_public_key = shlex.quote(public_key)
    command = " && ".join(
        [
            f"mkdir -p {shlex.quote(ssh_dir)}",
            f"chmod 700 {shlex.quote(ssh_dir)}",
            (
                f"if [ -f {quoted_private_key} ] && [ -f {quoted_public_key} ]; then "
                "printf 'already existed'; "
                f"elif [ -f {quoted_private_key} ]; then "
                f"ssh-keygen -y -f {quoted_private_key} > {quoted_public_key} && "
                "printf 'public key restored'; "
                f"elif [ -f {quoted_public_key} ]; then "
                "printf 'public key exists without private key' >&2; exit 1; "
                "else "
                f"ssh-keygen -t {KEY_TYPE} -f {quoted_private_key} -N '' >/dev/null && "
                "printf 'created'; fi"
            ),
        ]
    )
    status = run_remote(client, command).strip()
    public_key_content = run_remote(client, f"cat {shlex.quote(public_key)}").strip()
    if not public_key_content.startswith("ssh-ed25519 "):
        fail(f"Unexpected public key format in {public_key}.")

    return TargetKeyInfo(
        private_key_path=private_key,
        public_key_path=public_key,
        public_key=public_key_content,
        status=status,
    )


def ensure_target_known_host(client: "paramiko.SSHClient", borg_host: str) -> None:
    print(f"Adding Borg server {borg_host} to target known_hosts...")
    host_key_lines = scan_ssh_host_keys(borg_host)
    home = get_target_home(client)
    ssh_dir = f"{home}/.ssh"
    known_hosts = f"{ssh_dir}/known_hosts"
    command = " && ".join(
        [
            f"mkdir -p {shlex.quote(ssh_dir)}",
            f"chmod 700 {shlex.quote(ssh_dir)}",
            f"touch {shlex.quote(known_hosts)}",
            f"chmod 600 {shlex.quote(known_hosts)}",
        ]
    )
    try:
        run_remote(client, command)
        sftp = client.open_sftp()
        try:
            with sftp.open(known_hosts, "r") as remote_file:
                existing = remote_file.read().decode("utf-8", errors="replace")
            new_lines = [line for line in host_key_lines if line not in existing]
            if new_lines:
                with sftp.open(known_hosts, "a") as remote_file:
                    if existing and not existing.endswith("\n"):
                        remote_file.write("\n")
                    remote_file.write("\n".join(new_lines) + "\n")
        finally:
            sftp.close()
    except Exception as exc:
        fail(f"Could not add Borg server to target known_hosts: {exc}")


def verify_reverse_ssh(client: "paramiko.SSHClient", domain: str, borg_host: str) -> str:
    print(f"Checking reverse SSH from target to {domain}@{borg_host}...")
    remote_ssh_command = (
        f"ssh -o BatchMode=yes -o ConnectTimeout={SOCKET_TIMEOUT_SECONDS} "
        f"{shlex.quote(domain)}@{shlex.quote(borg_host)} "
        f"{shlex.quote('pwd; hostname; id')}"
    )
    try:
        output = run_remote(client, remote_ssh_command, timeout=COMMAND_TIMEOUT_SECONDS)
    except RuntimeError as exc:
        diagnostic = f"ssh {domain}@{borg_host} 'pwd; hostname; id'"
        fail(f"Reverse SSH check failed.\nManual diagnostic command on target:\n  {diagnostic}\n{exc}")

    first_line = output.splitlines()[0].strip() if output.splitlines() else ""
    expected_home = f"/home/{domain}"
    if first_line != expected_home:
        diagnostic = f"ssh {domain}@{borg_host} 'pwd; hostname; id'"
        fail(
            f"Reverse SSH returned unexpected working directory: {first_line!r}, "
            f"expected {expected_home!r}.\nManual diagnostic command on target:\n  {diagnostic}"
        )
    print("Reverse SSH check works.")
    return output


def print_report(
    borg_host: str,
    borg_user: BorgUserInfo,
    target_host: str,
    target_user: str,
    target_key: TargetKeyInfo,
    authorized_keys: Path,
    key_added: bool,
) -> None:
    password_value = borg_user.password if borg_user.password else "<existing user; not changed>"
    key_install_status = "added" if key_added else "already present"
    user_status = "created" if borg_user.created else "already existed"

    print()
    print("DONE")
    print()
    print("Borg server:")
    print(f"  host: {borg_host}")
    print()
    print("Backup identity:")
    print(f"  domain/user: {borg_user.username}")
    print(f"  home: {borg_user.home}")
    print(f"  user status: {user_status}")
    print(f"  password: {password_value}")
    print()
    print("Target server:")
    print(f"  host: {target_host}")
    print(f"  ssh user: {target_user}")
    print()
    print("Target SSH key used:")
    print(f"  private key: {target_key.private_key_path}")
    print(f"  public key: {target_key.public_key_path}")
    print(f"  status: {target_key.status}")
    print()
    print("Authorized key installed:")
    print(f"  path: {authorized_keys}")
    print(f"  status: {key_install_status}")
    print()
    print("Test command:")
    print(f"  ssh {borg_user.username}@{borg_host}")
    print()
    print("Future Borg repository base path:")
    print(f"  {borg_user.home}")


def main() -> None:
    require_root()
    require_paramiko()

    domain = prompt_required("Target domain: ")
    validate_domain_as_username(domain)
    resolve_host(domain)
    check_tcp_port(domain)

    target_user = prompt_required("Target SSH user: ")
    target_password = getpass.getpass("Target SSH password: ")
    if not target_password:
        fail("Empty SSH password is not allowed.")

    target_client = connect_target(domain, target_user, target_password)
    try:
        borg_host = prompt_borg_address()
        resolve_host(borg_host)

        ensure_local_known_host(domain)
        borg_user = create_borg_user(domain)
        authorized_keys = ensure_borg_ssh_files(borg_user)

        target_key = ensure_target_key(target_client)
        key_added = append_authorized_key(authorized_keys, target_key.public_key)
        ensure_borg_ssh_files(borg_user)

        ensure_target_known_host(target_client, borg_host)
        verify_reverse_ssh(target_client, domain, borg_host)

        print_report(
            borg_host=borg_host,
            borg_user=borg_user,
            target_host=domain,
            target_user=target_user,
            target_key=target_key,
            authorized_keys=authorized_keys,
            key_added=key_added,
        )
    finally:
        target_client.close()


if __name__ == "__main__":
    main()
