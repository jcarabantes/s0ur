import argparse
import random
import time
import sys

VALID_QUERIES = ["descriptions", "logged_users", "created_users", "juicy_groups", "get_fgpp_policies", "disabled_users"]

def parse_args() -> argparse.Namespace:
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
        "-q",
        "--query", 
        required=True, 
        help=f"Comma-separated queries to run. Options: {', '.join(VALID_QUERIES)} or 'all'"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode for verbose output."
    )
    parser.add_argument(
        "--delay", 
        type=int, 
        default=600, 
        help="Base delay (in seconds) between queries. Default: 600 (10 minutes)"
    )

    parser.add_argument(
        "--jitter", 
        type=int, 
        default=20, 
        help=f"Jitter percentage for delay randomness. Default: 20"
    )

    return parser.parse_args()

def wait_with_jitter(base_delay: int, jitter_percent: int) -> None:
    jitter_range = base_delay * (jitter_percent / 100)
    final_delay = base_delay + random.uniform(-jitter_range, jitter_range)
    final_delay = max(0, int(final_delay))  # convert to int and ensure positive

    print(f"[*] Sleeping for {final_delay} seconds (with jitter)...", end='', flush=True)

    for remaining in range(final_delay, 0, -1):
        sys.stdout.write(f"\r[*] Sleeping... {remaining:4d} seconds remaining")
        sys.stdout.flush()
        time.sleep(1)

    sys.stdout.write("\r[*] Done sleeping.                            \n")

def banner() -> None:
    print(r"""                             59                 
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
           80  000000000 000007000000000  05          v0.0.2 - jcarabantes - @Mr_RedSmasher
            00 2000000066000005800000003 08     
             603 00000070000000 000000 505      
               00  000 000000000 000  00        
                 000   600000004   000          
                    000004313400008             """)
    print("\n")
