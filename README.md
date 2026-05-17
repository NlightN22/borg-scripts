# Borg User Bootstrap

Interactive Python bootstrap script for preparing a dedicated Borg server user
and SSH access from a target server.

The script is intended to be run on the Borg/backup server as `root`. It creates
or reuses a Linux user named after the target domain, prepares SSH access, and
verifies that the target server can connect back to the Borg server with the
standard SSH key from the target user's home directory.

## Scope

This script does:

- check DNS and TCP/22 reachability for the target host;
- verify password-based SSH login to the target host;
- create a dedicated Borg server user when it does not exist;
- generate a random password for the new Borg server user;
- prepare `/home/<domain>/.ssh/authorized_keys`;
- create or reuse `~/.ssh/id_ed25519` on the target server;
- install the target public key into the Borg user's `authorized_keys`;
- update `known_hosts` in both directions;
- verify reverse SSH from the target server to the Borg server;
- print a final report for later Borgmatic or Docker configuration.

This script does not:

- configure Borgmatic;
- create Docker containers;
- configure database dumps;
- configure systemd timers;
- configure retention;
- run `borg init`;
- delete users or keys;
- overwrite existing target SSH keys.

## Requirements

On the Borg server:

```bash
apt install -y python3-paramiko openssh-client
```

On the target server:

- SSH server must be reachable on port `22`;
- password login must work for the selected SSH user;
- `ssh-keygen` must be available;
- SFTP subsystem must be enabled in SSH for automatic `known_hosts` setup.

## Usage

Run on the Borg server as `root`:

```bash
python3 bootstrap_borg_user.py
```

The script asks for:

- target domain;
- target SSH username;
- target SSH password;
- Borg server address, with `hostname -f` offered as the default.

If the Borg user already exists, the script asks whether to continue. It can
also generate and set a new password for the existing Borg user when needed,
for example after a previous interrupted bootstrap run.

Example values:

```text
Target domain: app.example.com
Target SSH user: root
Target SSH password: ********
Borg server address [backup.example.com]:
```

For the target domain `app.example.com`, the Borg identity will be:

```text
Borg user: app.example.com
Borg home: /home/app.example.com
```

## Final Report

At the end, the script prints the generated Borg user password and the SSH key
paths that should be used later in backup tooling.

Example:

```text
DONE

Borg server:
  host: backup.example.com

Backup identity:
  domain/user: app.example.com
  home: /home/app.example.com
  user status: created
  password: <generated-password>

Target server:
  host: app.example.com
  ssh user: root

Target SSH key used:
  private key: /root/.ssh/id_ed25519
  public key: /root/.ssh/id_ed25519.pub
  status: created

Authorized key installed:
  path: /home/app.example.com/.ssh/authorized_keys
  status: added

Test command:
  ssh app.example.com@backup.example.com

Future Borg repository base path:
  /home/app.example.com
```

## Security Notes

- The target server password is used only for the initial SSH session.
- The target server password is not written to disk.
- Existing `~/.ssh/id_ed25519` keys on the target server are not overwritten.
- Existing Borg server `authorized_keys` files are not overwritten.
- The generated Borg user password is printed once in the final report.
