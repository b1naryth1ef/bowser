# Bowser

Bowser is a modern and more secure SSH daemon and SSH CA intended for use as a bastion. By utilizing three factors of authentication, automatic generation and signing of single use SSH keys / certificates, and extensive logging, Bowser offers an extremely secure platform for performing SSH. Bowser was built at [Discord](https://discordapp.com/) to help us feel confident in the security of the most exposed and vulnerable piece of any infrastructure.

### Features
- Three-Factor authentication using SSH keys, passwords, and TOTP
- Automatic generation of signed SSH keys and certificates for access to proxied servers
- Extensive logging too multiple outlets
- Simple, auditable codebase

## Usage

### Example Config

```json
{
  "bind": "0.0.0.0:22",
  "discord_webhooks": ["https://canary.discordapp.com/api/webhooks/255545515817566228/my_discord_webhook_token"]
}
```

### Example Accounts

```json
[
  {
    "username": "andrei",
    "password": "$2a$15$QWu4umMh.ZRd5RtrMNkY4e0N197Uha8poioQsEn5spjz5brU8FIRK",
    "ssh-keys": [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCooBb+XKzBkDbr2qc1NM5iTRoaKXtjZPS0l9eOD+szEowHX5P+Ab4uvWcs6KUPcbITBZK60AN3Pi6mt5sTUQuqkFOGJolh6sDXpiBis7bkxQoDe11oOeHfBBHE5YfUaa7naLopN0cSXTkusY/ReNQDvIjQVjfmwoGA2pW96wV1oqnPDHz8HRUcHjfTdjovWY8xMRO0ZsHuavOdk8O+FYaD8BIO3i0bIa/tFe56Eme2FuCN77PgsHVA0HTzMAUGNpZU0zYsk8B5pjpQQyScSpE2ZfF2JqxcTl4KrnxWA3XtDtD3+lPR7ryWy+qDgrf9UxkuP7FEdIE6yD4lZdu0UdcD gopher@google.com"
    ],
    "mfa": {
      "totp": "AAAAAAAAAAAAAAAA"
    },
  }
]
```

### Example SSH Config

```
Host bastion
  Hostname bastion.my.corp
  Port 22
  ControlMaster auto
  ControlPath /tmp/ssh-control-%r@%h:%p
  ControlPersist 30m

Host credit-card-database1
  Hostname credit-card-database1.my.corp
  ProxyCommand ssh -W %h:%p bastion
```
