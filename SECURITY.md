# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | ✅ Yes             |
| < 3.0   | ❌ No              |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email: **security@example.com** (replace with your actual contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to understand and resolve the issue.

## Security Model

### Threat Model

This backup system is designed to protect against:

1. **Ransomware attacks** — Anomaly detection blocks suspicious changes
2. **Data corruption** — Integrity checks with `restic check`
3. **Unauthorized access** — AES-256 encryption at rest
4. **Injection attacks** — Input validation throughout
5. **Privilege escalation** — Runs as dedicated user (recommended)

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  config.yaml    │    │  credentials    │                │
│  │  (root:600)     │    │  (root:600)     │                │
│  └─────────────────┘    └─────────────────┘                │
│                              │                              │
│                              ▼                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              BACKUP SYSTEM (Python)                  │   │
│  │  • Input validation    • Path sanitization           │   │
│  │  • No shell=True       • Log sanitization            │   │
│  └─────────────────────────────────────────────────────┘   │
│                              │                              │
└──────────────────────────────┼──────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────┐
│                    UNTRUSTED ZONE                           │
│                              ▼                              │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  CIFS Sources   │    │  User Input     │                │
│  │  (Windows PCs)  │    │  (filenames)    │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Security Controls

### 1. Input Validation

All external inputs are validated before use:

```python
# Path validation - prevents traversal attacks
def validate_path(path: str, base_path: str = None) -> str:
    normalized = os.path.normpath(os.path.abspath(path))
    if '..' in normalized.split(os.sep):
        raise ValueError("Path traversal detected")
    if base_path:
        if not normalized.startswith(base_path + os.sep):
            raise ValueError("Path outside allowed directory")
    return normalized

# Hostname validation - prevents command injection
def validate_hostname(host: str) -> str:
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$', host):
        raise ValueError("Invalid hostname")
    return host
```

### 2. Command Injection Prevention

**All subprocess calls use lists, never strings with shell=True:**

```python
# ✅ CORRECT - commands as list
subprocess.run(["restic", "backup", path], capture_output=True)

# ❌ WRONG - never do this
subprocess.run(f"restic backup {path}", shell=True)  # VULNERABLE!
```

### 3. Path Traversal Protection

Every path is validated:

```python
# User provides: "../../etc/passwd"
# After validation: raises ValueError

# User provides: "/mnt/source/data"
# After validation: returns normalized path if within allowed base
```

### 4. Log Injection Prevention

Log messages are sanitized to prevent log forging:

```python
def sanitize_log_message(msg: str) -> str:
    sanitized = str(msg).replace('\n', '\\n').replace('\r', '\\r')
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized[:1000]  # Length limit
```

### 5. Credential Protection

- Credential files have `600` permissions (owner read/write only)
- Passwords are never logged
- Password file path validated before use

### 6. Symlink Protection

Directory scans don't follow symlinks to prevent symlink attacks:

```python
for root, dirs, files in os.walk(path, followlinks=False):
    # Safe iteration
```

## Security Checklist for Contributors

Before submitting code, verify:

- [ ] No `shell=True` in subprocess calls
- [ ] All user inputs validated with appropriate function
- [ ] No path traversal possible (`../` blocked)
- [ ] Log messages sanitized
- [ ] No credentials in logs
- [ ] Timeouts on all external operations
- [ ] Length limits on string inputs
- [ ] Error messages don't leak sensitive info

## Hardening Recommendations

### Production Deployment

1. **Run as dedicated user** (not root if possible)
   ```bash
   useradd -r -s /bin/false backup_system
   ```

2. **Restrict file permissions**
   ```bash
   chmod 600 /etc/backup_system/config.yaml
   chmod 600 /etc/backup_system/restic.password
   chmod 600 /etc/backup_system/creds_*
   ```

3. **Use firewall rules**
   ```bash
   # Only allow Backrest from trusted networks
   ufw allow from 192.168.1.0/24 to any port 9898
   ```

4. **Enable audit logging**
   ```bash
   auditctl -w /etc/backup_system/ -p wa -k backup_config
   ```

5. **Put Backrest behind reverse proxy with auth**
   ```nginx
   location / {
       auth_basic "Backup System";
       auth_basic_user_file /etc/nginx/.htpasswd;
       proxy_pass http://127.0.0.1:9898;
   }
   ```

### Network Security

1. Mount CIFS shares as read-only (`ro` option)
2. Use SMB signing and encryption (`seal` option)
3. Use dedicated backup service account with minimal permissions
4. Consider VPN or isolated network for backup traffic

### Monitoring

1. Monitor for failed backup attempts
2. Alert on anomaly detection triggers
3. Regular review of backup logs
4. Test restores periodically

## Known Limitations

1. **No authentication on Backrest by default** — Use reverse proxy
2. **Root privileges often required** — For mounting CIFS shares
3. **Password file is single point of failure** — Backup it securely!

## Security Updates

Security patches will be released as soon as possible after a vulnerability is confirmed. Monitor the repository's releases page for updates.

## Acknowledgments

Security review inspired by:
- OWASP Secure Coding Practices
- CWE/SANS Top 25 Most Dangerous Software Errors
- Python Security Best Practices
