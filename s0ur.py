from impacket.ldap import ldap
from simpleadusers import SimpleADUsers
from functions import VALID_QUERIES, parse_args, banner
import sys
import time
import getpass

# ToDo: 
# Continue detection based on: https://github.com/samratashok/Deploy-Deception/blob/master/Deploy-Deception.ps1
# Deploy-UserDeception
# Deploy-SlaveDeception
# Deploy-ComputerDeception
# Deploy-PrivilegedUserDeception
# check for Protection DenyLogon property (https://github.com/samratashok/Deploy-Deception/blob/master/Deploy-Deception.ps1#L779)
# Improve debug output too
# Add jitter or delays between each query to break a possible hunting chain analysis

def main():

    # s0ur.py ldap -dc-ip -d "DC=evilcorp,DC=local" -u username -p password
    # s0ur.py adws -dc-ip -d "DC=evilcorp,DC=local" -u username -p password
    # Test attrs: ldapsearch -x -b  dc=domain,dc=local -H ldap://192.168.1.10 -D "CN=M RS,CN=Users,DC=evilcorp,DC=local" -W
    # Specific query: ldapsearch -x -b  dc=domain,dc=local -H ldap://192.168.1.10 -D "CN=M RS,CN=Users,DC=evilcorp,DC=local" "(objectClass=group)" -W

    global debug
    args = parse_args()

    if not args.password:
        args.password = getpass.getpass("Password: ")

    if args.mode == "ldap":
        ad = SimpleADUsers(args.username, args.password, args.domain, args.dc_ip, args.debug, args.delay, args.jitter)

        try:
            ldap_conn = ldap.LDAPConnection(f'ldap://{ad.dc_ip}', ad.baseDN)
            ldap_conn.login(ad.username, ad.password, ad.domain.split(',')[0].split('=')[1])

            search_filter = "(&(objectCategory=person)(objectClass=user))"

            selected_queries = args.query.lower().split(",")

            # check if any query passed by the user is valid:
            invalid_queries = [q for q in selected_queries if q not in VALID_QUERIES]
            if invalid_queries:
                print(f"[!] Invalid query name(s): {', '.join(invalid_queries)}")
                sys.exit(1)

            if "all" in selected_queries: selected_queries = VALID_QUERIES.copy()
            if "descriptions" in selected_queries: ad.fetch_non_empty_descriptions(ldap_conn, search_filter)
            if "logged_users" in selected_queries: ad.never_logged(ldap_conn, search_filter)
            if "created_users" in selected_queries: ad.recent_users(ldap_conn, search_filter)

            if "juicy_groups" in selected_queries:
                juicy_groups = [
                    "Domain Admins",
                    "Enterprise Admins",
                    "Backup Operators",
                    "Account Operators",
                    "DNSAdmins",
                    "Print Operators",
                    "Server Operators",
                    "Remote Desktop Users",
                    "Power Users",
                    "Schema Admins"
                ]
                ad.get_members_of(ldap_conn, juicy_groups)
            
            # we'll search users and groups with msDS-PSOAppliesTo attr. the content of the Password Setting requires DA tho
            if "get_fgpp_policies" in selected_queries: ad.get_fgpp_policies(ldap_conn)

            # 1.2.840.113556.1.4.803 -> OID for bitwise AND: https://ldapwiki.com/wiki/Wiki.jsp?page=LDAP_MATCHING_RULE_BIT_AND
            # :=2 == 0x2 which is for disable accounts: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
            search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"

            if "disabled_users" in selected_queries: ad.disabled_users(ldap_conn, search_filter)

            ldap_conn.close()
            
        except ldap.LDAPSearchError as e:
            logging.error(f"LDAP search failed: {e}")    
    
    elif args.mode == "adws":
        print("[!] 'adws' mode is not yet implemented. TODO.")
    else:
        print("[-] Unknown mode.")

  
if __name__ == "__main__":
    banner()
    main()