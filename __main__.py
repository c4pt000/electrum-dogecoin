#!/usr/bin/env python2
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from decimal import Decimal
import json
import optparse
import os
import re
import ast
import sys
import time
import traceback


is_local = os.path.dirname(os.path.realpath(__file__)) == os.getcwd()
is_android = 'ANDROID_DATA' in os.environ

if is_local:
    sys.path.append('packages')

import __builtin__
__builtin__.use_local_modules = is_local or is_android

# load local module as electrum
if __builtin__.use_local_modules:
    import imp
    imp.load_module('electrum_doge', *imp.find_module('lib'))
    imp.load_module('electrum_doge_gui', *imp.find_module('gui'))


from electrum_doge import util
from electrum_doge import SimpleConfig, Network, Wallet, WalletStorage, NetworkProxy, Commands, known_commands, pick_random_server
from electrum_doge.util import print_msg, print_stderr, print_json, set_verbosity, InvalidPassword
from electrum_doge.daemon import get_daemon
from electrum_doge.plugins import init_plugins



# get password routine
def prompt_password(prompt, confirm=True):
    import getpass
    if sys.stdin.isatty():
        password = getpass.getpass(prompt)
        if password and confirm:
            password2 = getpass.getpass("Confirm: ")
            if password != password2:
                sys.exit("Error: Passwords do not match.")
    else:
        password = raw_input(prompt)
    if not password:
        password = None
    return password


def arg_parser():
    usage = "%prog [options] command"
    parser = optparse.OptionParser(usage=usage, add_help_option=False)
    parser.add_option("-h", "--help", action="callback", callback=print_help_cb, help="show this help text")
    parser.add_option("-g", "--gui", dest="gui", help="User interface: qt, lite, gtk, text or stdio")
    parser.add_option("-w", "--wallet", dest="wallet_path", help="wallet path (default: electrum-doge.dat)")
    parser.add_option("-o", "--offline", action="store_true", dest="offline", default=False, help="remain offline")
    parser.add_option("-d", "--daemon", action="store_true", dest="daemon", default=False, help="use daemon")
    parser.add_option("-C", "--concealed", action="store_true", dest="concealed", default=False, help="don't echo seed to console when restoring")
    parser.add_option("-a", "--all", action="store_true", dest="show_all", default=False, help="show all addresses")
    parser.add_option("-l", "--labels", action="store_true", dest="show_labels", default=False, help="show the labels of listed addresses")
    parser.add_option("-f", "--fee", dest="tx_fee", default=None, help="set tx fee")
    parser.add_option("-F", "--fromaddr", dest="from_addr", default=None, help="set source address for payto/mktx. if it isn't in the wallet, it will ask for the private key unless supplied in the format public_key:private_key. It's not saved in the wallet.")
    parser.add_option("-c", "--changeaddr", dest="change_addr", default=None, help="set the change address for payto/mktx. default is a spare address, or the source address if it's not in the wallet")
    parser.add_option("-s", "--server", dest="server", default=None, help="set server host:port:protocol, where protocol is either t (tcp), h (http), s (tcp+ssl), or g (https)")
    parser.add_option("-p", "--proxy", dest="proxy", default=None, help="set proxy [type:]host[:port], where type is socks4,socks5 or http")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="show debugging information")
    parser.add_option("-P", "--portable", action="store_true", dest="portable", default=False, help="portable wallet")
    parser.add_option("-L", "--lang", dest="language", default=None, help="defaut language used in GUI")
    parser.add_option("-G", "--gap", dest="gap_limit", default=None, help="gap limit")
    parser.add_option("-W", "--password", dest="password", default=None, help="set password for usage with commands (currently only implemented for create command, do not use it for longrunning gui session since the password is visible in /proc)")
    parser.add_option("-1", "--oneserver", action="store_true", dest="oneserver", default=False, help="connect to one server only")
    parser.add_option("--mpk", dest="mpk", default=False, help="restore from master public key")
    parser.add_option("-m", action="store_true", dest="hide_gui", default=False, help="hide GUI on startup")
    parser.add_option("--nbits", dest="nbits", default="128", help="number of bits for make_seed")
    parser.add_option("--entropy", dest="entropy", default="1", help="custom entropy for make_seed")
    return parser


def print_help(parser):
    parser.print_help()
    print_msg("Type 'electrum-doge help <command>' to see the help for a specific command")
    print_msg("Type 'electrum-doge --help' to see the list of options")
    run_command(known_commands['help'])


def print_help_cb(self, opt, value, parser):
    print_help(parser)
    sys.exit(1)


def run_command(cmd, password=None, args=None):
    if args is None:
        args = []  # Do not use mutables as default values!
    if cmd.requires_network and not options.offline:
        s = get_daemon(config, True)
        network = NetworkProxy(s, config)
        network.start()
        while network.is_connecting():
            time.sleep(0.1)
        if not network.is_connected():
            print_msg("daemon is not connected")
            sys.exit(1)
        if wallet:
            wallet.start_threads(network)
            wallet.update()
    else:
        network = None

    cmd_runner = Commands(wallet, network)
    func = getattr(cmd_runner, cmd.name)
    cmd_runner.password = password
    try:
        result = func(*args[1:])
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)


    if cmd.requires_network and not options.offline:
        if wallet:
            wallet.stop_threads()
        network.stop()


    if type(result) == str:
        print_msg(result)
    elif result is not None:
        print_json(result)



if __name__ == '__main__':

    wallet = None
    parser = arg_parser()
    options, args = parser.parse_args()
    if options.portable and options.wallet_path is None:
        options.electrum_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'electrum_data')

    # config is an object passed to the various constructors (wallet, interface, gui)
    if is_android:
        config_options = {
            'portable': True,
            'verbose': True,
            'gui': 'android',
            'auto_cycle': True,
        }
    else:
        config_options = eval(str(options))
        for k, v in config_options.items():
            if v is None:
                config_options.pop(k)

    set_verbosity(config_options.get('verbose'))

    config = SimpleConfig(config_options)

    if len(args) == 0:
        url = None
        cmd = 'gui'
    elif len(args) == 1 and re.match('^dogecoin:', args[0]):
        url = args[0]
        cmd = 'gui'
    else:
        cmd = args[0]

    if cmd == 'gui':
        init_plugins(config)
        gui_name = config.get('gui', 'classic')
        if gui_name in ['lite', 'classic']:
            gui_name = 'qt'
        try:
            gui = __import__('electrum_doge_gui.' + gui_name, fromlist=['electrum_doge_gui'])
        except ImportError:
            traceback.print_exc(file=sys.stdout)
            sys.exit()
            #sys.exit("Error: Unknown GUI: " + gui_name )

        # network interface
        if not options.offline:
            s = get_daemon(config, start_daemon=options.daemon)
            network = NetworkProxy(s, config)
            network.start()
        else:
            network = None

        gui = gui.ElectrumGui(config, network)
        gui.main(url)

        if network:
            network.stop()

        # we use daemon threads, their termination is enforced.
        # this sleep command gives them time to terminate cleanly.
        time.sleep(0.3)
        sys.exit(0)

    if cmd == 'daemon':
        arg = args[1] if len(args)>1 else None
        if arg not in ['start', 'stop', 'status']:
            print_msg("syntax: electrum daemon <start|status|stop>")
            sys.exit(1)
        s = get_daemon(config, False)
        if arg == 'start':
            if s:
                print_msg("Daemon already running")
                sys.exit(1) 
            get_daemon(config, True)
            sys.exit(0)
        elif arg in ['status','stop']:
            if not s:
                print_msg("Daemon not running")
                sys.exit(1)
            network = NetworkProxy(s, config)
            network.start()
            if arg == 'status':
                print_json({
                    'server': network.get_parameters()[0],
                    'blockchain_height': network.get_local_height(),
                    'server_height': network.get_server_height(),
                    'nodes': network.get_interfaces(),
                    'connected': network.is_connected()
                })
            elif arg == 'stop':
                network.stop_daemon()
                print_msg("Daemon stopped")
            network.stop()
        else:
            print "unknown command \"%s\""% arg
        sys.exit(0)


    if cmd not in known_commands:
        cmd = 'help'

    cmd = known_commands[cmd]

    # instanciate wallet for command-line
    storage = WalletStorage(config)

    if cmd.name in ['create', 'restore']:
        if storage.file_exists:
            sys.exit("Error: Remove the existing wallet first!")
        if options.password is not None:
            password = options.password
        elif cmd.name == 'restore' and options.mpk:
            password = None
        else:
            password = prompt_password("Password (hit return if you do not wish to encrypt your wallet):")

        # if config.server is set, the user either passed the server on command line
        # or chose it previously already. if he didn't pass a server on the command line,
        # we just pick up a random one.
        if not config.get('server'):
            config.set_key('server', pick_random_server())

        #fee = options.tx_fee if options.tx_fee else raw_input("fee (default:%s):" % (str(Decimal(wallet.fee)/100000000)))
        #gap = options.gap_limit if options.gap_limit else raw_input("gap limit (default 5):")
        #if fee:
        #    wallet.set_fee(float(fee)*100000000)
        #if gap:
        #    wallet.change_gap_limit(int(gap))

        if cmd.name == 'restore':
            if options.mpk:
                if Wallet.is_old_mpk(options.mpk):
                    wallet = Wallet.from_old_mpk(options.mpk, storage)
                if Wallet.is_xpub(options.mpk):
                    wallet = Wallet.from_xpub(options.mpk, storage)
            else:
                import getpass
                seed = getpass.getpass(prompt="seed:", stream=None) if options.concealed else raw_input("seed:")
                if not Wallet.is_seed(seed):
                    sys.exit("Error: Invalid seed")
                wallet = Wallet.from_seed(seed, storage)
                wallet.add_seed(seed, password)
                wallet.create_master_keys(password)
                wallet.create_main_account(password)

            if not options.offline:
                s = get_daemon(config, True)
                network = NetworkProxy(s,config)
                network.start()
                wallet.start_threads(network)
                print_msg("Recovering wallet...")
                wallet.restore(lambda x: x)
                if wallet.is_found():
                    print_msg("Recovery successful")
                else:
                    print_msg("Warning: Found no history for this wallet")
            else:
                wallet.synchronize()
                print_msg("Warning: This wallet was restored offline. It may contain more addresses than displayed.")

        else:
            wallet = Wallet(storage)
            seed = wallet.make_seed()
            wallet.add_seed(seed, password)
            wallet.create_master_keys(password)
            wallet.create_main_account(password)
            wallet.synchronize()
            print_msg("Your wallet generation seed is:\n\"%s\"" % seed)
            print_msg("Please keep it in a safe place; if you lose it, you will not be able to restore your wallet.")


        print_msg("Wallet saved in '%s'" % wallet.storage.path)

        # terminate
        sys.exit(0)


    if cmd.name not in ['create', 'restore'] and cmd.requires_wallet and not storage.file_exists:
        print_msg("Error: Wallet file not found.")
        print_msg("Type 'electrum create' to create a new wallet, or provide a path to a wallet with the -w option")
        sys.exit(0)


    if cmd.requires_wallet:
        wallet = Wallet(storage)
    else:
        wallet = None


    # important warning
    if cmd.name in ['dumpprivkey', 'dumpprivkeys']:
        print_stderr("WARNING: ALL your private keys are secret.")
        print_stderr("Exposing a single private key can compromise your entire wallet!")
        print_stderr("In particular, DO NOT use 'redeem private key' services proposed by third parties.")

    # commands needing password
    if cmd.requires_password:
        if wallet.seed == '':
            seed = ''
            password = None
        elif wallet.use_encryption:
            password = prompt_password('Password:', False)
            if not password:
                print_msg("Error: Password required")
                sys.exit(1)
            # check password
            try:
                seed = wallet.get_seed(password)
            except InvalidPassword:
                print_msg("Error: This password does not decode this wallet.")
                sys.exit(1)
        else:
            password = None
            seed = wallet.get_seed(None)
    else:
        password = None

    # add missing arguments, do type conversions
    if (cmd.name == 'importprivkey' and len(args)==1)\
       or (cmd.name == 'signtxwithkey' and len(args)==2):
        # See if they specificed a key on the cmd line, if not prompt
        args.append(prompt_password('Enter PrivateKey (will not echo):', False))

    elif cmd.name == 'createmultisig':
        args = [cmd, int(args[1]), json.loads(args[2])]

    elif cmd.name == 'createrawtransaction':
        args = [cmd, json.loads(args[1]), json.loads(args[2])]

    elif cmd.name == 'listaddresses':
        args = [cmd, options.show_all, options.show_labels]

    elif cmd.name == 'make_seed':
        args = [cmd, int(options.nbits), long(options.entropy), options.language]

    elif cmd.name in ['payto', 'mktx']:
        domain = [options.from_addr] if options.from_addr else None
        args = ['mktx', args[1], Decimal(args[2]), Decimal(options.tx_fee) if options.tx_fee else None, options.change_addr, domain]

    elif cmd.name in ['paytomany', 'mksendmanytx']:
        domain = [options.from_addr] if options.from_addr else None
        outputs = []
        for i in range(1, len(args), 2):
            if len(args) < i+2:
                print_msg("Error: Mismatched arguments.")
                sys.exit(1)
            outputs.append((args[i], Decimal(args[i+1])))
        args = ['mksendmanytx', outputs, Decimal(options.tx_fee) if options.tx_fee else None, options.change_addr, domain]

    elif cmd.name == 'help':
        if len(args) < 2:
            print_help(parser)
            sys.exit(1)

    # check the number of arguments
    if len(args) - 1 < cmd.min_args:
        print_msg("Not enough arguments")
        print_msg("Syntax:", cmd.syntax)
        sys.exit(1)

    if cmd.max_args >= 0 and len(args) - 1 > cmd.max_args:
        print_msg("too many arguments", args)
        print_msg("Syntax:", cmd.syntax)
        sys.exit(1)

    if cmd.max_args < 0:
        if len(args) > cmd.min_args + 1:
            message = ' '.join(args[cmd.min_args:])
            print_msg("Warning: Final argument was reconstructed from several arguments:", repr(message))
            args = args[0:cmd.min_args] + [message]

    if cmd.name == 'check_seed':
        args.append(long(options.entropy))
        args.append(options.language)


    # run the command
    if cmd.name == 'deseed':
        if not wallet.seed:
            print_msg("Error: This wallet has no seed")
        else:
            ns = wallet.storage.path + '.seedless'
            print_msg("Warning: you are going to create a seedless wallet'\nIt will be saved in '%s'" % ns)
            if raw_input("Are you sure you want to continue? (y/n) ") in ['y', 'Y', 'yes']:
                wallet.storage.path = ns
                wallet.seed = ''
                wallet.storage.put('seed', '', True)
                wallet.use_encryption = False
                wallet.storage.put('use_encryption', wallet.use_encryption, True)
                for k in wallet.imported_keys.keys():
                    wallet.imported_keys[k] = ''
                wallet.storage.put('imported_keys', wallet.imported_keys, True)
                print_msg("Done.")
            else:
                print_msg("Action canceled.")

    elif cmd.name == 'getconfig':
        key = args[1]
        out = config.get(key)
        print_msg(out)

    elif cmd.name == 'setconfig':
        key, value = args[1:3]
        try:
            value = ast.literal_eval(value)
        except:
            pass
        config.set_key(key, value, True)
        print_msg(True)

    elif cmd.name == 'password':
        new_password = prompt_password('New password:')
        wallet.update_password(password, new_password)

    else:
        run_command(cmd, password, args)

    time.sleep(0.1)
    sys.exit(0)
