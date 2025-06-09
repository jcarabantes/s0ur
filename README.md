# s0ur — AD Honeypot Detection via LDAP (Alpha)

**Very early alpha version — work in progress.**  
This script performs specific LDAP queries against an Active Directory environment to help identify **potential honeypots** or decoy accounts.

The goal is to support red teams, pentesers and researchers in spotting traps set up in the AD environment.



> ⚠️ **Disclaimer**
> This tool does **not automatically** detect honeypots or deceptions in Active Directory.
> It collects and lists data points (e.g. user descriptions, creation dates, group memberships) that might help you to identify suspicious accounts based on context and experience.
>
> Think of it as a helper for manual analysis — not a detection engine.


## What It Does (Currently)

The script connects to the Domain Controller via **LDAP** and lists user objects with a focus on signs of deception.

Currently, it:

* **Lists user descriptions** so you can manually check for possible passwords
  (e.g. `"Password123"` stored in the `description` field)
* **Shows users who have never logged in**
  (based on a missing or zeroed `lastLogon` attribute)
* **Displays account creation dates**
  so you can identify **recently created users** that may be suspicious
* **Retrieves members of high-privilege or interesting groups**
  (like `Backup Operators`, `DnsAdmins`, etc.) — useful for detecting **fake privileged users**

These can all be signals of decoy or trap accounts used in **Active Directory environments**.

---

## Usage

```bash
python3 s0ur.py ldap -dc-ip 192.168.1.10 -d "DC=evilcorp,DC=local" -u admin
```

# Example
```bash
python s0ur.py ldap -dc-ip 192.168.1.10 -d "DC=evilcorp,DC=local" -u "admin" -p $(cat ../password)
                             59                                                                          
                         10007                                                                           
   50000000003         300000                                                                            
      30000000000     0000001                                                                            
        50000000700  3000000                                                                             
          00000000207000000                                                                              
           800000000 41  26962                                                                           
               4001200083     200003                                                                     
                 005   000000000   400                                                                   
               00  000 000000000 000  00                                                                 
             00  000000 0000000 000000  00          _     ______                                                                                                                                                  
            00 0000000082000007000000009 00        | |   / __   |                                                                                                                                                 
           00  0000000003000002000000000  08        \ \ | | //| |_   _  ____ ____  _   _                                                                                                                          
           0  09 70000000 000 0000000  90 10         \ \| |// | | | | |/ ___)  _ \| | | |                                                                                                                         
          00 0000000  0000 0 0008  0000000 08    _____) )  /__| | |_| | |_  | | | | |_| |                                                                                                                         
          00 000000000005 3 1 400000000000 00   (______/ \_____/ \____|_(_) | ||_/ \__  |                                                                                                                         
          00 00000000008  8 8  00000000000 00                               |_|   (____/                                                                                                                          
          80 0000002 20000 0 00003 5000000 09                                                            
           01 1  80000000 000 00000009 71 20    A python tool that may help to detect AD Honeypots                                                                                                                
           80  000000000 000007000000000  05          v0.1.0 - jcarabantes - @Mr_RedSmasher                                                                                                                       
            00 2000000066000005800000003 08                                                              
             603 00000070000000 000000 505                                                               
               00  000 000000000 000  00                                                                 
                 000   600000004   000                                                                   
                    000004313400008                                                                      


Showing users that have no logon date               
+------------------+-------------+                  
| sAMAccountName   | lastLogon   |                  
|------------------+-------------|                  
| Guest            | <never>     |                  
| krbtgt           | <never>     |                  
| user1            | <never>     |                  
| user2            | <never>     |                  
+------------------+-------------+
```