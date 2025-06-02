import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Enumerate LDAP users and attributes from Active Directory using Impacket."
    )
    parser.add_argument(
        "mode",
        choices=["ldap", "adws"],
        help="Protocol to use: 'ldap' (implemented) or 'adws' (TODO)."
    )
    parser.add_argument(
        "-dc-ip",
        required=True,
        help="IP address of the Domain Controller."
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help='Domain in LDAP format, e.g., "DC=evilcorp,DC=local".'
    )
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="Username to authenticate with."
    )
    parser.add_argument(
        "-p", "--password",
        help="Password. If not provided, it will prompt."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode for verbose output."
    )
    return parser.parse_args()