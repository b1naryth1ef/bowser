- Read accounts from plaintext file:
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
[X] - Basic SSH daemon
[X] - Basic Console logging
[ ] - MFA
[ ] - Adding accounts
[ ] - Tracking logins (database + logfile)
[ ] - Tracking logins (slack + discord)

