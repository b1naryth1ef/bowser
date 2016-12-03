# Bowser

Bowser is a SSH daemon built to be a more secure and auditable version of the standard OpenSSH. Bowser supports MFA/TOTP out of the box, includes extensive logging, and supports recording/replaying of PTY sessions.

### Features

- SSH/PTY Support
- Multi-Factor authentication using TOTP
- Extensive session logging for auditing
- Ability to record and replay all PTY sessions
- Logging of sessions to SQLite

## Example Bowser Configuration

```json
{
  "bind": "0.0.0.0:22",
  "motd": "Google Inc. SSH",
  "accounts": "/etc/bowser/accounts.json",
  "id_rsa": "/etc/bowser/id_rsa",
}
```

## Example Account Configuration
```json
{
  "username": "andrei",
  "ssh-keys": [
    "ssh-rsa ....",
    "ssh-rsa ...."
  ],
  "mfa": {
    "totp": "ADFSFSDFSDF"
  },
  "scopes": [
    "production"
  ],
  "shell": "zsh"
}
```

# TODO
- [x] Basic SSH daemon
- [x] Basic Console logging
- [x] MFA
- [ ] Adding accounts (CLI)
- [ ] Proper logging / file based logging
- [ ] SQLite for logging sessions
- [ ] Slack webhook
- [ ] Discord webhook
