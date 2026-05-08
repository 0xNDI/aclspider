# aclspider

Spiders SMB shares and reports directories with non-standard ACLs, highlighting write permissions for the current user.

Inspired by [smbclient-ng](https://github.com/p0dalirius/smbclient-ng).

## Setup

```
uv tool install git+https://github.com/0xNDI/aclspider
```

## Usage

```
# Auto-detect groups via SAMR, show write ACEs only
aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP --write-only

# Confirm write access is not blocked at share level
aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP --write-only --test-write

# Pass-the-hash
aclspider 10.10.11.x -u alice -H :aad3b435b51404eeaad3b435b51404ee -d CORP --write-only

# Kerberos (uses KRB5CCNAME or --ccache)
aclspider 10.10.11.x -u alice -k -d CORP --dc-ip 10.10.11.1

# Scan specific shares only
aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP -s SYSVOL Data

# Show all non-admin ACEs (no user filter)
aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP --no-filter

# JSON output
aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP --write-only --json
```
