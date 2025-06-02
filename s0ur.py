from pprint import pprint
from impacket.ldap import ldap
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.ldap.ldapasn1 import SearchResultEntry #usefull for handling the ASN1 format  
from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.samr import SAMPR_USER_INFO_BUFFER
from impacket.dcerpc.v5 import transport
from datetime import datetime
from config import *
import logging
import sys
import time

# ToDo: 
# - pending analysis of userAccountControl
# Continue detection based on: https://github.com/samratashok/Deploy-Deception/blob/master/Deploy-Deception.ps1
# Deploy-UserDeception
# Deploy-SlaveDeception
# Deploy-ComputerDeception
# Deploy-PrivilegedUserDeception
# check for Protection DenyLogon property (https://github.com/samratashok/Deploy-Deception/blob/master/Deploy-Deception.ps1#L779)

# Test attrs: ldapsearch -x -b  dc=domain,dc=local -H ldap://192.168.200.200 -D "CN=M RS,CN=Users,DC=domain,DC=local" -W


# Simplified class from GetADUsers.py
class SimpleADUsers:
    def __init__(self, username, password, domain, dc_ip):
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip

        self.baseDN = ','.join([f'dc={part}' for part in domain.replace('DC=', '').split(',')])
        # self.header = ["sAMAccountName", "description", "lastLogon", "userAccountControl"]
        self.properties = ["sAMAccountName", "pwdLastSet", "lastLogon", "description"]
       
        self.colLen = [20, 30, 19, 19]
        self.outputFormat = ' '.join(['{%d:%ds}' % (i, w) for i, w in enumerate(self.colLen)])

    def _getUnixTime(self, t):
        t -= 116444736000000000
        t //= 10000000
        return t

    def _processRecord(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        pwdLastSet = ''
        mail = ''
        lastLogon = 'N/A'
        description = 'N/A'

        if debug: print(item['attributes'])

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    name = attribute['vals'][0].asOctets().decode('utf-8')
                    if not name.endswith('$'):
                        sAMAccountName = name
                elif attr_type == 'pwdLastSet':
                    val = int(str(attribute['vals'][0]))
                    pwdLastSet = "<never>" if val == 0 else str(datetime.fromtimestamp(self.getUnixTime(val)))
                elif attr_type == 'lastLogon':
                    val = int(str(attribute['vals'][0]))
                    lastLogon = "<never>" if val == 0 else str(datetime.fromtimestamp(self.getUnixTime(val)))
                # elif attr_type == 'mail':
                #     mail = str(attribute['vals'][0])
                elif attr_type == 'description':
                    description = str(attribute['vals'][0])

            if sAMAccountName:
                # ["sAMAccountName", "description", "lastLogon", "userAccountControl","whenCreated"]
                # print(self.outputFormat.format(sAMAccountName, description, mail, pwdLastSet, lastLogon))
                print(self.outputFormat.format(sAMAccountName, pwdLastSet, lastLogon, description))

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def processDescription(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        description = None

        if debug: print("processDescription", item['attributes'])

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    name = attribute['vals'][0].asOctets().decode('utf-8')
                    if not name.endswith('$'):
                        sAMAccountName = name
                elif attr_type == 'description':
                    # val = 
                    description = str(attribute['vals'][0])

            if sAMAccountName and description:
                # ["sAMAccountName", "description", "lastLogon", "userAccountControl","whenCreated"]
                # print(self.outputFormat.format(sAMAccountName, description, mail, pwdLastSet, lastLogon))
                print((sAMAccountName, description))

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def processLastLogon(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        lastLogon = None

        if debug: print("processLastLogon", item['attributes'])

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    name = attribute['vals'][0].asOctets().decode('utf-8')
                    if not name.endswith('$'):
                        sAMAccountName = name
                elif attr_type == 'lastLogon':
                    val = int(str(attribute['vals'][0]))
                    lastLogon = "<never>" if val == 0 else str(datetime.fromtimestamp(self._getUnixTime(val)))

            if sAMAccountName and lastLogon == "<never>":
                # ["sAMAccountName", "description", "lastLogon", "userAccountControl","whenCreated"]
                # print(self.outputFormat.format(sAMAccountName, description, mail, pwdLastSet, lastLogon))
                print((sAMAccountName, lastLogon))

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def fetch_non_empty_descriptions(self, ldap_conn, search_filter):
        print("Showing users' description if there's any passwords, care.")
        sc = ldap.SimplePagedResultsControl(size=100)
        ldap_conn.search(searchFilter=search_filter,
                            attributes=["sAMAccountName", "description"],
                            searchControls=[sc],
                            perRecordCallback=self.processDescription)
           
    def never_logged(self, ldap_conn, search_filter):
        print("Showing users that have no logon date")
        sc = ldap.SimplePagedResultsControl(size=100)
        ldap_conn.search(searchFilter=search_filter,
                             attributes=["sAMAccountName", "lastLogon"],
                             searchControls=[sc],
                             perRecordCallback=self.processLastLogon)

    def run(self):
        print(self.outputFormat.format(*self.properties))
        print('  '.join(['-' * l for l in self.colLen]))

        try:
            ldap_conn = ldap.LDAPConnection(f'ldap://{self.dc_ip}', self.baseDN)
            ldap_conn.login(self.username, self.password, self.domain.split(',')[0].split('=')[1])

            search_filter = "(&(objectCategory=person)(objectClass=user))"
            sc = ldap.SimplePagedResultsControl(size=100)
            ldap_conn.search(searchFilter=search_filter,
                             attributes=self.properties,
                             searchControls=[sc],
                             perRecordCallback=self.processRecord)

            ldap_conn.close()

        except ldap.LDAPSearchError as e:
            logging.error(f"LDAP search failed: {e}")

# s0ur.py ldap -dc-ip -d "DC=evilcorp,DC=local" -u username -p password
# s0ur.py adws -dc-ip -d "DC=evilcorp,DC=local" -u username -p password

def main():
    global debug
    debug = False if len(sys.argv) == 1 else True

    ad = SimpleADUsers(username, password, domain, dc_ip)

    try:
        ldap_conn = ldap.LDAPConnection(f'ldap://{ad.dc_ip}', ad.baseDN)
        ldap_conn.login(ad.username, ad.password, ad.domain.split(',')[0].split('=')[1])

        search_filter = "(&(objectCategory=person)(objectClass=user))"

        # check for obvious descriptions like passwords and be carefull
        ad.fetch_non_empty_descriptions(ldap_conn, search_filter)

        # never logged users
        ad.never_logged(ldap_conn, search_filter)

        ldap_conn.close()
    except ldap.LDAPSearchError as e:
        logging.error(f"LDAP search failed: {e}")



    # recent users creation
    # ad.recent_users()

    # users in juicy groups can also be a problem
    # ad.get_members_of(['Backup Operators','etc'])

    # extract the Fine-Grained Password Policies (FGPP) or users or groups may help to detect
    # users with bad passwords policies > possible honeypots
    # ad.get_password_policies() # pending test first policies.py

    # ad.run()
    
    # executer = GetADUsers(username, password, domain, options)
    # executer.run()

    # users = get_domain_users(dc_ip, domain, username, password)
    # for user in users: print(user)
  
if __name__ == "__main__":
    main()