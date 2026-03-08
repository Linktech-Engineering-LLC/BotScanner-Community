# SSH Keys: Generation, Management, and Cross‑Platform Setup

## Overview
This document provides a clean, public‑safe reference for generating, managing, and using SSH keys across Windows, WSL, and Linux environments.  
It follows best practices:
- One keypair per environment  
- Never copy private keys between machines  
- Use ED25519 unless a system requires RSA  
- Use descriptive comments for audit clarity  

---

## 1. Generate a New SSH Keypair

### Windows (PowerShell)
```powershell
ssh-keygen -t ed25519 -C "windows-to-github"
```

### WSL (Ubuntu / openSUSE / Debian)
```bash
ssh-keygen -t ed25519 -C "wsl-to-github"
```

### Linux (Server or Workstation)
```bash
ssh-keygen -t ed25519 -C "linux-to-github"
```

Keys are created in:
```
$HOME/.ssh/id_ed25519
$HOME/.ssh/id_ed25519.pub
```

---

## 2. Permissions (Linux / WSL)
```bash
chmod 700 "$HOME/.ssh"
chmod 600 "$HOME/.ssh/id_ed25519"
chmod 644 "$HOME/.ssh/id_ed25519.pub"
```

---

## 3. Add Public Key to Remote Host
Copy the **public** key only:

```bash
ssh-copy-id -i "$HOME/.ssh/id_ed25519.pub" <username>@<hostname>
```

Or manually append:

```bash
cat "$HOME/.ssh/id_ed25519.pub" >> "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
```

---

## 4. SSH Config Examples

### Windows → Linux host
```sshconfig
Host linux-host
    HostName 192.0.2.50
    User <remote-username>
    IdentityFile %USERPROFILE%/.ssh/id_ed25519
    IdentitiesOnly yes
```

### WSL → GitHub
```sshconfig
Host github.com
    User git
    HostName github.com
    IdentityFile $HOME/.ssh/id_ed25519
    IdentitiesOnly yes
```

### Linux → Multiple Hosts
```sshconfig
Host test-router
    HostName 198.51.100.1
    User <remote-username>
    IdentityFile $HOME/.ssh/router_ed25519

Host test-proxmox
    HostName 203.0.113.20
    User <remote-username>
    IdentityFile $HOME/.ssh/proxmox_ed25519
```

*(All IPs above use RFC‑5737 TEST‑NET ranges: safe for documentation.)*

---

## 5. Testing Keys
```bash
ssh -v linux-host
```

Verbose mode confirms which key is offered and accepted.

---

## 6. GitHub Key Setup

### Add key to GitHub
```bash
cat "$HOME/.ssh/id_ed25519.pub"
```

Paste into:  
**GitHub → Settings → SSH and GPG Keys → New SSH Key**

### Test GitHub access
```bash
ssh -T git@github.com
```

---

## 7. Backup Strategy
- Backup **public keys** freely  
- Backup **private keys** only to encrypted storage  
- Never move private keys between machines  
- Never email or paste private keys  

---

## 8. Troubleshooting

### “Permission denied (publickey)”
Check:
```bash
chmod 700 "$HOME/.ssh"
chmod 600 "$HOME/.ssh/id_ed25519"
```

### Wrong key offered
```bash
ssh -v <host>
```

Look for:
```
Offering public key: ...
```

### Force a specific key
```bash
ssh -i "$HOME/.ssh/id_ed25519" <username>@<host>
```

---

## 9. Recommended Key Naming
Use descriptive, audit‑friendly names:

```
id_ed25519_windows
id_ed25519_wsl
id_ed25519_linux
id_ed25519_router
id_ed25519_github
```

---

## 10. Public‑Safe Notes
- No private key material is ever shown  
- No real hostnames, IPs, or usernames  
- All examples use RFC‑5737 test networks  
- All paths use `$HOME` or `%USERPROFILE%` for portability  

---

## End of Document