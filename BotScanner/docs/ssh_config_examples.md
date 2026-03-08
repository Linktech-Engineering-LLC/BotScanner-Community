# SSH Config Examples

This document provides clean, environment‑agnostic SSH configuration examples for Windows, WSL, and Linux.  
All examples use:
- `$HOME` or `%USERPROFILE%` for portability  
- RFC‑5737 documentation‑safe IP ranges  
- Generic usernames  
- ED25519 keys  

---

## 1. Windows → Linux Host

```sshconfig
Host linux-host
    HostName 192.0.2.50
    User <remote-username>
    IdentityFile %USERPROFILE%/.ssh/id_ed25519
    IdentitiesOnly yes
```

---

## 2. WSL → GitHub

```sshconfig
Host github.com
    User git
    HostName github.com
    IdentityFile $HOME/.ssh/id_ed25519
    IdentitiesOnly yes
```

---

## 3. Linux → Multiple Hosts

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

---

## 4. Forcing a Specific Key

```sshconfig
Host special-host
    HostName 203.0.113.99
    User <remote-username>
    IdentityFile $HOME/.ssh/special_ed25519
    IdentitiesOnly yes
```

---

## 5. Optional: Disable Password Auth Per‑Host

```sshconfig
Host secure-host
    HostName 192.0.2.77
    User <remote-username>
    IdentityFile $HOME/.ssh/secure_ed25519
    PasswordAuthentication no
    IdentitiesOnly yes
```

---

## Notes
- All IPs are from RFC‑5737 TEST‑NET ranges and safe for documentation.  
- No real usernames, hosts, or paths appear in this file.  
- This document is intended to be referenced by `ssh_keys.md` and the project README.

---

## End of Document