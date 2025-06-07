from impacket.ldap import ldap
from simpleadusers import SimpleADUsers
from functions import *
import sys
import time
import getpass

# ToDo: 
# - pending analysis of userAccountControl
# Continue detection based on: https://github.com/samratashok/Deploy-Deception/blob/master/Deploy-Deception.ps1
# Deploy-UserDeception
# Deploy-SlaveDeception
# Deploy-ComputerDeception
# Deploy-PrivilegedUserDeception
# check for Protection DenyLogon property (https://github.com/samratashok/Deploy-Deception/blob/master/Deploy-Deception.ps1#L779)
# add --query all or specific ldap query (such as just non-empty descriptions, etc.)
# Test attrs: ldapsearch -x -b  dc=domain,dc=local -H ldap://192.168.1.10 -D "CN=M RS,CN=Users,DC=evilcorp,DC=local" -W
# Improve debug output too

def main():

    # s0ur.py ldap -dc-ip -d "DC=evilcorp,DC=local" -u username -p password
    # s0ur.py adws -dc-ip -d "DC=evilcorp,DC=local" -u username -p password

    global debug
    args = parse_args()
    #debug = args.debug

    if not args.password:
        args.password = getpass.getpass("Password: ")

    if args.mode == "ldap":
        ad = SimpleADUsers(args.username, args.password, args.domain, args.dc_ip, args.debug)

        try:
            ldap_conn = ldap.LDAPConnection(f'ldap://{ad.dc_ip}', ad.baseDN)
            ldap_conn.login(ad.username, ad.password, ad.domain.split(',')[0].split('=')[1])

            search_filter = "(&(objectCategory=person)(objectClass=user))"

            # check for obvious descriptions like passwords and be carefull
            ad.fetch_non_empty_descriptions(ldap_conn, search_filter)

            # never logged users
            ad.never_logged(ldap_conn, search_filter)

            # recent users creation
            ad.recent_users(ldap_conn, search_filter)

            ldap_conn.close()
        except ldap.LDAPSearchError as e:
            logging.error(f"LDAP search failed: {e}")    
    
    elif args.mode == "adws":
        print("[!] 'adws' mode is not yet implemented. TODO.")
    else:
        print("[-] Unknown mode.")

    # users in juicy groups can also be a problem
    # ad.get_members_of(['Backup Operators','etc'])

    # extract the Fine-Grained Password Policies (FGPP) or users or groups may help to detect
    # users with bad passwords policies > possible honeypots
    # ad.get_password_policies() # pending test first policies.py
  
if __name__ == "__main__":
    banner()
    main()