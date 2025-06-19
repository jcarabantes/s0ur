from impacket.ldap import ldap
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.ldap.ldapasn1 import SearchResultEntry #usefull for handling the ASN1 format  
from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.samr import SAMPR_USER_INFO_BUFFER
from impacket.dcerpc.v5 import transport
from tabulate import tabulate
from datetime import datetime
import logging

# Simplified class from GetADUsers.py
class SimpleADUsers:
    
    def __init__(self, username, password, domain, dc_ip, debug):
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.debug = debug

        self.baseDN = ','.join([f'dc={part}' for part in domain.replace('DC=', '').split(',')])
        
        self.attributes_list = [
            ["sAMAccountName", "description"],
            ["sAMAccountName", "lastLogon"],
            ["sAMAccountName", "whenCreated"],
            ["samAccountName", "member"]
        ]
        self.rows = [] # this will be used with tabulate when printing results
        
    def _getUnixTime(self, t):
        t -= 116444736000000000
        t //= 10000000
        return t

    def _changeGeneralizedTime(self, gt):
        
        # whenCreated and other fields return values like: whenCreated: 20250320064604.0Z and whenChanged: 20250320064749.0Z
        # remove 0Z from the LDAP output
        noZ = gt.split('.')[0]
        formated_date = datetime.strptime(noZ, "%Y%m%d%H%M%S")
        return formated_date.strftime("%Y-%m-%d %H:%M:%S")

    def _processRecord(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        pwdLastSet = ''
        mail = ''
        lastLogon = 'N/A'
        whenCreated = 'N/A'

        if self.debug: print(item['attributes'])

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    name = attribute['vals'][0].asOctets().decode('utf-8')
                    if not name.endswith('$'):
                        sAMAccountName = name
                elif attr_type == 'pwdLastSet':
                    val = int(str(attribute['vals'][0]))
                    pwdLastSet = "<never>" if val == 0 else str(datetime.fromtimestamp(self._getUnixTime(val)))
                elif attr_type == 'lastLogon':
                    val = int(str(attribute['vals'][0]))
                    lastLogon = "<never>" if val == 0 else str(datetime.fromtimestamp(self._getUnixTime(val)))
                # elif attr_type == 'mail':
                #     mail = str(attribute['vals'][0])
                elif attr_type == 'whenCreated':
                    val = str(attribute['vals'][0])
                    whenCreated = str(self._changeGeneralizedTime(val))
                   # description = str(attribute['vals'][0])
                elif attr_type == 'description':
                    description = str(attribute['vals'][0])

            if sAMAccountName:
                # ["sAMAccountName", "description", "lastLogon", "userAccountControl","whenCreated"]
                # print(self.outputFormat.format(sAMAccountName, description, mail, pwdLastSet, lastLogon))
                print(self.outputFormat.format(sAMAccountName, pwdLastSet, lastLogon, whenCreated))

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def _draw_table(self, headers) -> None:
        print(tabulate(self.rows, headers=headers, tablefmt="psql"))
        # we clear the rows for the next execution
        self.rows.clear()

    def processDescription(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        description = None

        if self.debug: print("processDescription", item['attributes'])

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
                #print(self.attributes_list[0])
                #print((sAMAccountName, description))
                self.rows.append([sAMAccountName, description])

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def processLastLogon(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        lastLogon = None

        if self.debug: print("processLastLogon", item['attributes'])

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
                #print((sAMAccountName, lastLogon))
                self.rows.append([sAMAccountName, lastLogon])

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def processWhenCreated(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        sAMAccountName = ''
        lastLogon = None

        if self.debug: print("processWhenCreated", item['attributes'])

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    name = attribute['vals'][0].asOctets().decode('utf-8')
                    if not name.endswith('$'):
                        sAMAccountName = name
                elif attr_type == 'whenCreated':
                    val = str(attribute['vals'][0])
                    whenCreated = str(self._changeGeneralizedTime(val))

            if sAMAccountName and whenCreated:
                #print((sAMAccountName, whenCreated))
                self.rows.append([sAMAccountName, whenCreated])

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing record: {e}")

    def processGroupMembers(self, item):
        if not isinstance(item, SearchResultEntry):
            return

        group_name = ""
        members = []

        if self.debug: print("processGroupMembers", item['attributes'])

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    group_name = attribute['vals'][0].asOctets().decode('utf-8')
                elif attr_type == 'member':
                    members = [str(m) for m in attribute['vals']]

            if group_name and members:
                for member in members:
                    self.rows.append([group_name, member])

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing group members: {e}")


    def processFGPP(self,item):
        if not isinstance(item, SearchResultEntry):
            return

        name = ""
        fgpp = None

        try:
            for attribute in item['attributes']:
                attr_type = str(attribute['type'])
                if attr_type == 'sAMAccountName':
                    name = attribute['vals'][0].asOctets().decode('utf-8')
                elif attr_type == 'msDS-PSOApplied':
                    fgpp = str(attribute['vals'][0])

            if name and fgpp:
                self.rows.append([name, fgpp])

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error(f"Error processing FGPP record: {e}")

    def fetch_non_empty_descriptions(self, ldap_conn, search_filter):
        print("Showing users' description if there's any passwords, care.")
        sc = ldap.SimplePagedResultsControl(size=100)
        ldap_conn.search(searchFilter=search_filter,
                            attributes=self.attributes_list[0],
                            searchControls=[sc],
                            perRecordCallback=self.processDescription)
        self._draw_table(self.attributes_list[0])
           
    def never_logged(self, ldap_conn, search_filter):
        print("Showing users that have no logon date")
        sc = ldap.SimplePagedResultsControl(size=100)
        ldap_conn.search(searchFilter=search_filter,
                             attributes=self.attributes_list[1],
                             searchControls=[sc],
                             perRecordCallback=self.processLastLogon)
        self._draw_table(self.attributes_list[1])

    def recent_users(self, ldap_conn, search_filter):
        print("Showing creation date for each user")
        sc = ldap.SimplePagedResultsControl(size=100)
        ldap_conn.search(searchFilter=search_filter,
                             attributes=self.attributes_list[2],
                             searchControls=[sc],
                             perRecordCallback=self.processWhenCreated)
        self._draw_table(self.attributes_list[2])

    def get_members_of(self, ldap_conn, groups):
        print("Showing members of juicy groups")
        sc = ldap.SimplePagedResultsControl(size=100)

        for group in groups:
            # You can filter by CN or sAMAccountName (some envs use CN=Backup Operators, some just the name)
            group_filter = f"(&(objectClass=group)(sAMAccountName={group}))"
            ldap_conn.search(
                searchFilter=group_filter,
                attributes=self.attributes_list[3],
                searchControls=[sc],
                perRecordCallback=self.processGroupMembers)

        self._draw_table(self.attributes_list[3])

    def get_fgpp_policies(self, ldap_conn):
        print("Listing users and groups with Fine-Grained Password Policies (FGPP) applied")
        sc = ldap.SimplePagedResultsControl(size=100)

        # Search users
        user_filter = "(&(objectCategory=person)(objectClass=user)(msDS-PSOApplied=*))"
        ldap_conn.search(searchFilter=user_filter,
                        attributes=["sAMAccountName", "msDS-PSOApplied"],
                        searchControls=[sc],
                        perRecordCallback=self.processFGPP)

        # Search groups
        group_filter = "(&(objectCategory=group)(msDS-PSOApplied=*))"
        ldap_conn.search(searchFilter=group_filter,
                        attributes=["sAMAccountName", "msDS-PSOApplied"],
                        searchControls=[sc],
                        perRecordCallback=self.processFGPP)

        if self.rows:
            self._draw_table(["Name", "FGPP Applied"])
        else:
            print("[-] No users or groups found with FGPP applied.")
