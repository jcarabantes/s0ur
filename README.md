# s0ur — AD Honeypot Detection via LDAP (Alpha)

**Very early alpha version — work in progress.**  
This script performs specific LDAP queries against an Active Directory environment to help identify **potential honeypots** or decoy accounts.

The goal is to support red teams, pentesers and researchers in spotting traps set up in the AD environment.

---

## What It Does (Currently)

The script connects to the Domain Controller via **LDAP** and lists user objects with a focus on signs of deception.

It looks for:

- **Descriptions that might include passwords**  
  (e.g. "Password123" in the `description` field)
- **Users that have never logged in**  
  (`lastLogon` field is missing or zero)
- **Recently created accounts**  
  (`whenCreated` within a short timeframe)

These can all be signals of decoy or trap accounts used in **Active Directory environments**.

---

## Usage

```bash
python3 s0ur.py ldap -dc-ip 192.168.1.10 -d "DC=evilcorp,DC=local" -u admin