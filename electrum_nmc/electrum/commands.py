#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import datetime
import copy
import argparse
import json
import ast
import base64
import operator
import asyncio
import inspect
from functools import wraps, partial
from itertools import repeat
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Dict, List

from .import util, ecc
from .util import bfh, bh2u, format_satoshis, json_decode, json_encode, is_hash256_str, is_hex_str, to_bytes, timestamp_to_datetime
from .util import standardize_path
from . import bitcoin
from .bitcoin import is_address,  hash_160, COIN
from .bip32 import BIP32Node
from .i18n import _
from .names import build_name_commitment, build_name_new, format_name_identifier, name_expires_in, name_identifier_to_scripthash, OP_NAME_NEW, OP_NAME_FIRSTUPDATE, OP_NAME_UPDATE, validate_value_length
from .verifier import verify_tx_is_in_block
from .transaction import (Transaction, multisig_script, TxOutput, PartialTransaction, PartialTxOutput,
                          tx_from_any, PartialTxInput, TxOutpoint)
from .invoices import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .synchronizer import Notifier
from .wallet import Abstract_Wallet, create_new_wallet, restore_wallet_from_text, Deterministic_Wallet
from .address_synchronizer import TX_HEIGHT_LOCAL
from .mnemonic import Mnemonic
from .lnutil import SENT, RECEIVED
from .lnutil import LnFeatures
from .lnutil import ln_dummy_address
from .lnpeer import channel_id_from_funding_tx
from .plugin import run_hook
from .version import ELECTRUM_VERSION
from .simple_config import SimpleConfig
from .invoices import LNInvoice
from . import submarine_swaps
from . import constants


if TYPE_CHECKING:
    from .network import Network
    from .daemon import Daemon


known_commands = {}  # type: Dict[str, Command]


class NotSynchronizedException(Exception):
    pass


class NameNotFoundError(Exception):
    pass

class NameUnconfirmedError(NameNotFoundError):
    pass

class NameExpiredError(NameNotFoundError):
    pass

class NameNeverExistedError(NameNotFoundError):
    pass

class NameAlreadyExistsError(Exception):
    pass

class NamePreRegistrationNotFound(Exception):
    pass

class NamePreRegistrationPendingError(Exception):
    pass

class NameUpdatedTooRecentlyError(Exception):
    pass

def satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN*Decimal(amount)) if amount not in ['!', None] else amount

def format_satoshis(x):
    return str(Decimal(x)/COIN) if x is not None else None

def json_normalize(x):
    # note: The return value of commands, when going through the JSON-RPC interface,
    #       is json-encoded. The encoder used there cannot handle some types, e.g. electrum.util.Satoshis.
    # note: We should not simply do "json_encode(x)" here, as then later x would get doubly json-encoded.
    # see #5868
    return json_decode(json_encode(x))


class Command:
    def __init__(self, func, s):
        self.name = func.__name__
        self.requires_network = 'n' in s
        self.requires_wallet = 'w' in s
        self.requires_password = 'p' in s
        self.description = func.__doc__
        self.help = self.description.split('.')[0] if self.description else None
        varnames = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.defaults = func.__defaults__
        if self.defaults:
            n = len(self.defaults)
            self.params = list(varnames[:-n])
            self.options = list(varnames[-n:])
        else:
            self.params = list(varnames)
            self.options = []
            self.defaults = []

        # sanity checks
        if self.requires_password:
            assert self.requires_wallet
        for varname in ('wallet_path', 'wallet'):
            if varname in varnames:
                assert varname in self.options
        assert not ('wallet_path' in varnames and 'wallet' in varnames)
        if self.requires_wallet:
            assert 'wallet' in varnames


def command(s):
    def decorator(func):
        global known_commands
        name = func.__name__
        known_commands[name] = Command(func, s)
        @wraps(func)
        async def func_wrapper(*args, **kwargs):
            cmd_runner = args[0]  # type: Commands
            cmd = known_commands[func.__name__]  # type: Command
            password = kwargs.get('password')
            daemon = cmd_runner.daemon
            if daemon:
                if 'wallet_path' in cmd.options and kwargs.get('wallet_path') is None:
                    kwargs['wallet_path'] = daemon.config.get_wallet_path()
                if cmd.requires_wallet and kwargs.get('wallet') is None:
                    kwargs['wallet'] = daemon.config.get_wallet_path()
                if 'wallet' in cmd.options:
                    wallet_path = kwargs.get('wallet', None)
                    if isinstance(wallet_path, str):
                        wallet = daemon.get_wallet(wallet_path)
                        if wallet is None:
                            raise Exception('wallet not loaded')
                        kwargs['wallet'] = wallet
            wallet = kwargs.get('wallet')  # type: Optional[Abstract_Wallet]
            if cmd.requires_wallet and not wallet:
                raise Exception('wallet not loaded')
            if cmd.requires_password and password is None and wallet.has_password():
                raise Exception('Password required')
            return await func(*args, **kwargs)
        return func_wrapper
    return decorator


class Commands:

    def __init__(self, *, config: 'SimpleConfig',
                 network: 'Network' = None,
                 daemon: 'Daemon' = None, callback=None):
        self.config = config
        self.daemon = daemon
        self.network = network
        self._callback = callback

    def _run(self, method, args, password_getter=None, **kwargs):
        """This wrapper is called from unit tests and the Qt python console."""
        cmd = known_commands[method]
        password = kwargs.get('password', None)
        wallet = kwargs.get('wallet', None)
        if (cmd.requires_password and wallet and wallet.has_password()
                and password is None):
            password = password_getter()
            if password is None:
                return

        f = getattr(self, method)
        if cmd.requires_password:
            kwargs['password'] = password

        if 'wallet' in kwargs:
            sig = inspect.signature(f)
            if 'wallet' not in sig.parameters:
                kwargs.pop('wallet')

        coro = f(*args, **kwargs)
        fut = asyncio.run_coroutine_threadsafe(coro, asyncio.get_event_loop())
        result = fut.result()

        if self._callback:
            self._callback()
        return result

    @command('')
    async def commands(self):
        """List of commands"""
        return ' '.join(sorted(known_commands.keys()))

    @command('n')
    async def getinfo(self):
        """ network info """
        net_params = self.network.get_parameters()
        response = {
            'path': self.network.config.path,
            'server': net_params.server.host,
            'blockchain_height': self.network.get_local_height(),
            'server_height': self.network.get_server_height(),
            'spv_nodes': len(self.network.get_interfaces()),
            'connected': self.network.is_connected(),
            'auto_connect': net_params.auto_connect,
            'version': ELECTRUM_VERSION,
            'default_wallet': self.config.get_wallet_path(),
            'fee_per_kb': self.config.fee_per_kb(),
        }
        return response

    @command('n')
    async def stop(self):
        """Stop daemon"""
        self.daemon.stop()
        return "Daemon stopped"

    @command('n')
    async def list_wallets(self):
        """List wallets open in daemon"""
        return [{'path': path, 'synchronized': w.is_up_to_date()}
                for path, w in self.daemon.get_wallets().items()]

    @command('n')
    async def load_wallet(self, wallet_path=None, password=None):
        """Open wallet in daemon"""
        wallet = self.daemon.load_wallet(wallet_path, password, manual_upgrades=False)
        if wallet is not None:
            run_hook('load_wallet', wallet, None)
        response = wallet is not None
        return response

    @command('n')
    async def close_wallet(self, wallet_path=None):
        """Close wallet"""
        return self.daemon.stop_wallet(wallet_path)

    @command('')
    async def create(self, passphrase=None, password=None, encrypt_file=True, seed_type=None, wallet_path=None):
        """Create a new wallet.
        If you want to be prompted for an argument, type '?' or ':' (concealed)
        """
        d = create_new_wallet(path=wallet_path,
                              passphrase=passphrase,
                              password=password,
                              encrypt_file=encrypt_file,
                              seed_type=seed_type,
                              config=self.config)
        return {
            'seed': d['seed'],
            'path': d['wallet'].storage.path,
            'msg': d['msg'],
        }

    @command('')
    async def restore(self, text, passphrase=None, password=None, encrypt_file=True, wallet_path=None):
        """Restore a wallet from text. Text can be a seed phrase, a master
        public key, a master private key, a list of namecoin addresses
        or namecoin private keys.
        If you want to be prompted for an argument, type '?' or ':' (concealed)
        """
        # TODO create a separate command that blocks until wallet is synced
        d = restore_wallet_from_text(text,
                                     path=wallet_path,
                                     passphrase=passphrase,
                                     password=password,
                                     encrypt_file=encrypt_file,
                                     config=self.config)
        return {
            'path': d['wallet'].storage.path,
            'msg': d['msg'],
        }

    @command('wp')
    async def password(self, password=None, new_password=None, wallet: Abstract_Wallet = None):
        """Change wallet password. """
        if wallet.storage.is_encrypted_with_hw_device() and new_password:
            raise Exception("Can't change the password of a wallet encrypted with a hw device.")
        b = wallet.storage.is_encrypted()
        wallet.update_password(password, new_password, encrypt_storage=b)
        wallet.save_db()
        return {'password':wallet.has_password()}

    @command('w')
    async def get(self, key, wallet: Abstract_Wallet = None):
        """Return item from wallet storage"""
        return wallet.db.get(key)

    @command('')
    async def getconfig(self, key):
        """Return a configuration variable. """
        return self.config.get(key)

    @classmethod
    def _setconfig_normalize_value(cls, key, value):
        if key not in ('rpcuser', 'rpcpassword'):
            value = json_decode(value)
            try:
                value = ast.literal_eval(value)
            except:
                pass
        return value

    @command('')
    async def setconfig(self, key, value):
        """Set a configuration variable. 'value' may be a string or a Python expression."""
        value = self._setconfig_normalize_value(key, value)
        self.config.set_key(key, value)
        return True

    @command('')
    async def get_ssl_domain(self):
        """Check and return the SSL domain set in ssl_keyfile and ssl_certfile
        """
        return self.config.get_ssl_domain()

    @command('')
    async def make_seed(self, nbits=132, language=None, seed_type=None):
        """Create a seed"""
        from .mnemonic import Mnemonic
        s = Mnemonic(language).make_seed(seed_type, num_bits=nbits)
        return s

    @command('n')
    async def getaddresshistory(self, address):
        """Return the transaction history of any address. Note: This is a
        walletless server query, results are not checked by SPV.
        """
        sh = bitcoin.address_to_scripthash(address)
        return await self.network.get_history_for_scripthash(sh)

    @command('w')
    async def listunspent(self, wallet: Abstract_Wallet = None):
        """List unspent outputs. Returns the list of unspent transaction
        outputs in your wallet."""
        coins = []
        for txin in wallet.get_utxos():
            d = txin.to_json()
            v = d.pop("value_sats")
            d["value"] = str(Decimal(v)/COIN) if v is not None else None
            coins.append(d)
        return coins

    @command('wn')
    async def name_list(self, identifier=None, name_encoding='ascii', value_encoding='ascii', wallet: Abstract_Wallet = None):
        """List unspent name outputs. Returns the list of unspent name_anyupdate
        outputs in your wallet."""

        coins = await self.listunspent(wallet=wallet)

        result = []

        for coin in coins:
            name_op = coin["name_op"]

            if name_op is None:
                continue

            if "name" not in name_op:
                continue

            if name_encoding == "hex":
                name = name_op["name"]
            elif name_encoding == "ascii":
                name_bytes = bfh(name_op["name"])
                name = name_bytes.decode("ascii")
            else:
                raise Exception('Unsupported name_encoding "{}"'.format(name_encoding))

            if value_encoding == "hex":
                value = name_op["value"]
            elif value_encoding == "ascii":
                value_bytes = bfh(name_op["value"])
                value = value_bytes.decode("ascii")
            else:
                raise Exception('Unsupported value_encoding "{}"'.format(value_encoding))

            # Skip this item if it doesn't match the requested identifier
            if identifier is not None:
                if identifier != name:
                    continue

            txid = coin["prevout_hash"]
            vout = coin["prevout_n"]

            address = coin["address"]

            height = coin["height"]
            chain_height = self.network.get_local_height()

            expires_in = name_expires_in(height, chain_height)
            expired = expires_in <= 0 if expires_in is not None else None

            is_mine = wallet.is_mine(address)

            result_item = {
                "name": name,
                "name_encoding": name_encoding,
                "value": value,
                "value_encoding": value_encoding,
                "txid": txid,
                "vout": vout,
                "address": address,
                "height": height,
                "expires_in": expires_in,
                "expired": expired,
                "ismine": is_mine,
            }
            result.append(result_item)

        return result

    @command('n')
    async def getaddressunspent(self, address):
        """Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.
        """
        sh = bitcoin.address_to_scripthash(address)
        return await self.network.listunspent_for_scripthash(sh)

    @command('')
    async def serialize(self, jsontx):
        """Create a transaction from json inputs.
        Inputs must have a redeemPubkey.
        Outputs must be a list of {'address':address, 'value':satoshi_amount}.
        """
        keypairs = {}
        inputs = []  # type: List[PartialTxInput]
        locktime = jsontx.get('lockTime', 0)
        for txin_dict in jsontx.get('inputs'):
            if txin_dict.get('prevout_hash') is not None and txin_dict.get('prevout_n') is not None:
                prevout = TxOutpoint(txid=bfh(txin_dict['prevout_hash']), out_idx=int(txin_dict['prevout_n']))
            elif txin_dict.get('output'):
                prevout = TxOutpoint.from_str(txin_dict['output'])
            else:
                raise Exception("missing prevout for txin")
            txin = PartialTxInput(prevout=prevout)
            txin._trusted_value_sats = int(txin_dict['value'])
            sec = txin_dict.get('privkey')
            if sec:
                txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
                pubkey = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
                keypairs[pubkey] = privkey, compressed
                txin.script_type = txin_type
                txin.pubkeys = [bfh(pubkey)]
                txin.num_sig = 1
            inputs.append(txin)

        outputs = [PartialTxOutput.from_address_and_value(txout['address'], int(txout['value']))
                   for txout in jsontx.get('outputs')]
        tx = PartialTransaction.from_io(inputs, outputs, locktime=locktime)
        tx.sign(keypairs)
        return tx.serialize()

    @command('wp')
    async def signtransaction(self, tx, privkey=None, password=None, wallet: Abstract_Wallet = None):
        """Sign a transaction. The wallet keys will be used unless a private key is provided."""
        tx = PartialTransaction(tx)
        if privkey:
            txin_type, privkey2, compressed = bitcoin.deserialize_privkey(privkey)
            pubkey = ecc.ECPrivkey(privkey2).get_public_key_bytes(compressed=compressed).hex()
            tx.sign({pubkey:(privkey2, compressed)})
        else:
            wallet.sign_transaction(tx, password)
        return tx.serialize()

    @command('')
    async def deserialize(self, tx):
        """Deserialize a serialized transaction"""
        tx = tx_from_any(tx)
        return tx.to_json()

    @command('n')
    async def broadcast(self, tx):
        """Broadcast a transaction to the network. """
        tx = Transaction(tx)
        await self.network.broadcast_transaction(tx)
        return tx.txid()

    @command('')
    async def createmultisig(self, num, pubkeys):
        """Create multisig address"""
        assert isinstance(pubkeys, list), (type(num), type(pubkeys))
        redeem_script = multisig_script(pubkeys, num)
        address = bitcoin.hash160_to_p2sh(hash_160(bfh(redeem_script)))
        return {'address':address, 'redeemScript':redeem_script}

    @command('w')
    async def freeze(self, address, wallet: Abstract_Wallet = None):
        """Freeze address. Freeze the funds at one of your wallet\'s addresses"""
        return wallet.set_frozen_state_of_addresses([address], True)

    @command('w')
    async def unfreeze(self, address, wallet: Abstract_Wallet = None):
        """Unfreeze address. Unfreeze the funds at one of your wallet\'s address"""
        return wallet.set_frozen_state_of_addresses([address], False)

    @command('wp')
    async def getprivatekeys(self, address, password=None, wallet: Abstract_Wallet = None):
        """Get private keys of addresses. You may pass a single wallet address, or a list of wallet addresses."""
        if isinstance(address, str):
            address = address.strip()
        if is_address(address):
            return wallet.export_private_key(address, password)
        domain = address
        return [wallet.export_private_key(address, password) for address in domain]

    @command('wp')
    async def getprivatekeyforpath(self, path, password=None, wallet: Abstract_Wallet = None):
        """Get private key corresponding to derivation path (address index).
        'path' can be either a str such as "m/0/50", or a list of ints such as [0, 50].
        """
        return wallet.export_private_key_for_path(path, password)

    @command('w')
    async def ismine(self, address, wallet: Abstract_Wallet = None):
        """Check if address is in wallet. Return true if and only address is in wallet"""
        return wallet.is_mine(address)

    @command('')
    async def dumpprivkeys(self):
        """Deprecated."""
        return "This command is deprecated. Use a pipe instead: 'electrum-radc listaddresses | electrum-radc getprivatekeys - '"

    @command('')
    async def validateaddress(self, address):
        """Check that an address is valid. """
        return is_address(address)

    @command('w')
    async def getpubkeys(self, address, wallet: Abstract_Wallet = None):
        """Return the public keys for a wallet address. """
        return wallet.get_public_keys(address)

    @command('w')
    async def getbalance(self, wallet: Abstract_Wallet = None):
        """Return the balance of your wallet. """
        c, u, x = wallet.get_balance()
        l = wallet.lnworker.get_balance() if wallet.lnworker else None
        out = {"confirmed": str(Decimal(c)/COIN)}
        if u:
            out["unconfirmed"] = str(Decimal(u)/COIN)
        if x:
            out["unmatured"] = str(Decimal(x)/COIN)
        if l:
            out["lightning"] = str(Decimal(l)/COIN)
        return out

    @command('n')
    async def getaddressbalance(self, address):
        """Return the balance of any address. Note: This is a walletless
        server query, results are not checked by SPV.
        """
        sh = bitcoin.address_to_scripthash(address)
        out = await self.network.get_balance_for_scripthash(sh)
        out["confirmed"] =  str(Decimal(out["confirmed"])/COIN)
        out["unconfirmed"] =  str(Decimal(out["unconfirmed"])/COIN)
        return out

    @command('n')
    async def getmerkle(self, txid, height):
        """Get Merkle branch of a transaction included in a block. Electrum
        uses this to verify transactions (Simple Payment Verification)."""
        return await self.network.get_merkle_for_transaction(txid, int(height))

    @command('n')
    async def getservers(self):
        """Return the list of known servers (candidates for connecting)."""
        return self.network.get_servers()

    @command('')
    async def version(self):
        """Return the version of Electrum."""
        from .version import ELECTRUM_VERSION
        return ELECTRUM_VERSION

    @command('w')
    async def getmpk(self, wallet: Abstract_Wallet = None):
        """Get master public key. Return your wallet\'s master public key"""
        return wallet.get_master_public_key()

    @command('wp')
    async def getmasterprivate(self, password=None, wallet: Abstract_Wallet = None):
        """Get master private key. Return your wallet\'s master private key"""
        return str(wallet.keystore.get_master_private_key(password))

    @command('')
    async def convert_xkey(self, xkey, xtype):
        """Convert xtype of a master key. e.g. xpub -> ypub"""
        try:
            node = BIP32Node.from_xkey(xkey)
        except:
            raise Exception('xkey should be a master public/private key')
        return node._replace(xtype=xtype).to_xkey()

    @command('wp')
    async def getseed(self, password=None, wallet: Abstract_Wallet = None):
        """Get seed phrase. Print the generation seed of your wallet."""
        s = wallet.get_seed(password)
        return s

    @command('wp')
    async def importprivkey(self, privkey, password=None, wallet: Abstract_Wallet = None):
        """Import a private key."""
        if not wallet.can_import_privkey():
            return "Error: This type of wallet cannot import private keys. Try to create a new wallet with that key."
        try:
            addr = wallet.import_private_key(privkey, password)
            out = "Keypair imported: " + addr
        except Exception as e:
            out = "Error: " + repr(e)
        return out

    def _resolver(self, x, wallet):
        if x is None:
            return None
        out = wallet.contacts.resolve(x)
        if out.get('type') == 'openalias' and self.nocheck is False and out.get('validated') is False:
            raise Exception('cannot verify alias', x)
        return out['address']

    @command('n')
    async def sweep(self, privkey, destination, fee=None, nocheck=False, imax=100):
        """Sweep private keys. Returns a transaction that spends UTXOs from
        privkey to a destination address. The transaction is not
        broadcasted."""
        from .wallet import sweep
        tx_fee = satoshis(fee)
        privkeys = privkey.split()
        self.nocheck = nocheck
        #dest = self._resolver(destination)
        tx = sweep(privkeys,
                   network=self.network,
                   config=self.config,
                   to_address=destination,
                   fee=tx_fee,
                   imax=imax)
        return tx.serialize() if tx else None

    @command('wp')
    async def signmessage(self, address, message, password=None, wallet: Abstract_Wallet = None):
        """Sign a message with a key. Use quotes if your message contains
        whitespaces"""
        sig = wallet.sign_message(address, message, password)
        return base64.b64encode(sig).decode('ascii')

    @command('')
    async def verifymessage(self, address, signature, message):
        """Verify a signature."""
        sig = base64.b64decode(signature)
        message = util.to_bytes(message)
        return ecc.verify_message_with_address(address, sig, message)

    @command('wp')
    async def payto(self, destination, amount, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None,
                    nocheck=False, unsigned=False, rbf=None, password=None, locktime=None, wallet: Abstract_Wallet = None):
        """Create a transaction. """
        self.nocheck = nocheck
        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))
        amount_sat = satoshis(amount)
        outputs = [PartialTxOutput.from_address_and_value(destination, amount_sat)]
        tx = wallet.create_transaction(
            outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            unsigned=unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime)
        return tx.serialize()

    @command('wp')
    async def paytomany(self, outputs, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None,
                        nocheck=False, unsigned=False, rbf=None, password=None, locktime=None, wallet: Abstract_Wallet = None):
        """Create a multi-output transaction. """
        self.nocheck = nocheck
        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))
        final_outputs = []
        for address, amount in outputs:
            address = self._resolver(address, wallet)
            amount_sat = satoshis(amount)
            final_outputs.append(PartialTxOutput.from_address_and_value(address, amount_sat))
        tx = wallet.create_transaction(
            final_outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            unsigned=unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime)
        return tx.serialize()

    @command('wp')
    async def name_new(self, identifier, destination=None, amount=0.0, outputs=[], fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None, nocheck=False, unsigned=False, rbf=None, password=None, locktime=None, allow_existing=False, wallet: Abstract_Wallet = None):
        """Create a name_new transaction. """
        self.nocheck = nocheck
        if not allow_existing:
            name_exists = True
            try:
                show = await self.name_show(identifier)
            except NameNotFoundError:
                name_exists = False
            if name_exists:
                raise NameAlreadyExistsError("The name is already registered")

        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))

        # TODO: support non-ASCII encodings
        # TODO: enforce length limit on identifier
        identifier_bytes = identifier.encode("ascii")
        memo = "Pre-Registration: " + format_name_identifier(identifier_bytes)

        if destination is None:
            request = await self.add_request(None, memo=memo, wallet=wallet)
            destination = request['address']

        name_op, rand = build_name_new(identifier_bytes, address=destination, password=password, wallet=wallet)

        final_outputs = []
        for o_address, o_amount in outputs:
            o_address = self._resolver(o_address, wallet)
            amount_sat = satoshis(o_amount)
            final_outputs.append(PartialTxOutput.from_address_and_value(o_address, amount_sat))
        destination = self._resolver(destination, wallet)
        amount_sat = satoshis(amount)
        name_output = PartialTxOutput.from_address_and_value(destination, amount_sat)
        name_output.add_name_op(name_op)
        final_outputs.append(name_output)

        tx = wallet.create_transaction(
            final_outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            unsigned=unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime)
        return {"tx": tx.serialize(), "txid": tx.txid(), "rand": bh2u(rand)}

    @command('wp')
    async def name_firstupdate(self, identifier, rand=None, name_new_txid=None, value="", destination=None, amount=0.0, outputs=[], fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None, nocheck=False, unsigned=False, rbf=None, password=None, locktime=None, allow_early=False, wallet: Abstract_Wallet = None):
        """Create a name_firstupdate transaction. """
        self.nocheck = nocheck
        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))

        # TODO: support non-ASCII encodings
        # TODO: enforce length limits on identifier and value
        # TODO: enforce exact length of rand
        identifier_bytes = identifier.encode("ascii")
        value_bytes = value.encode("ascii")

        if rand is None:
            if name_new_txid is None:
                txid_filter = None
            else:
                txid_filter = [name_new_txid]
            # Get a list of inputs.  If the user supplied an input txid, use
            # that as a hint.
            name_inputs = wallet.get_spendable_coins(None, include_names=True, only_uno_txids=txid_filter)
            # Check all the inputs to see if any of them have a commitment that
            # matches the salt we can calculate.
            for new_input in name_inputs:
                # Skip any inputs that aren't a name_new.
                if new_input.name_op is None:
                    continue
                new_op = new_input.name_op
                if new_op["op"] != OP_NAME_NEW:
                    continue

                # Calculate the salt
                address = new_input.address
                rand_bytes = wallet.name_salt(identifier_bytes, address, password)

                # Calculate the commitment, and check if it matches
                commitment = build_name_commitment(identifier_bytes, rand_bytes)
                if commitment == new_op["hash"]:
                    # We found the commitment.
                    name_new_txid = new_input.prevout.txid.hex()
                    break
            else:
                raise NamePreRegistrationNotFound("name_new input with matching commitment not found")
        else:
            rand_bytes = bfh(rand)

        if not allow_early:
            conf = wallet.get_tx_height(name_new_txid).conf
            if conf < 12:
                remaining_conf = 12 - conf
                raise NamePreRegistrationPendingError("The name pre-registration is still pending; wait " + str(remaining_conf) + " more blocks")

        name_op = {"op": OP_NAME_FIRSTUPDATE, "name": identifier_bytes, "rand": rand_bytes, "value": value_bytes}
        memo = "Registration: " + format_name_identifier(identifier_bytes)

        if destination is None:
            request = await self.add_request(None, memo=memo, wallet=wallet)
            destination = request['address']

        final_outputs = []
        for o_address, o_amount in outputs:
            o_address = self._resolver(o_address, wallet)
            amount_sat = satoshis(o_amount)
            final_outputs.append(PartialTxOutput.from_address_and_value(o_address, amount_sat))
        destination = self._resolver(destination, wallet)
        amount_sat = satoshis(amount)
        name_output = PartialTxOutput.from_address_and_value(destination, amount_sat)
        name_output.add_name_op(name_op)
        final_outputs.append(name_output)

        tx = wallet.create_transaction(
            final_outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            unsigned=unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime,
            name_input_txids=[name_new_txid])
        return tx.serialize()

    @command('wpn')
    async def name_update(self, identifier, value=None, destination=None, amount=0.0, outputs=[], fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None, nocheck=False, unsigned=False, rbf=None, password=None, locktime=None, wallet: Abstract_Wallet = None):
        """Create a name_update transaction. """

        self.nocheck = nocheck
        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))

        # Allow renewing a name without any value changes by omitting the
        # value.
        renew = False
        if value is None:
            list_results = await self.name_list(identifier, wallet=wallet)
            list_results = list_results[0]

            # This check is in place to prevent an attack where an ElectrumX
            # server supplies an unconfirmed name_update transaction with a
            # malicious value and then tricks the wallet owner into signing a
            # name renewal with that malicious value.  expires_in is None when
            # the transaction has 0 confirmations.
            expires_in = list_results["expires_in"]
            if expires_in is None or expires_in > constants.net.NAME_EXPIRATION - 12:
                raise NameUpdatedTooRecentlyError("Name was updated too recently to safely determine current value.  Either wait or specify an explicit value.")

            value = list_results["value"]
            renew = True

        # TODO: support non-ASCII encodings
        # TODO: enforce length limits on identifier and value
        identifier_bytes = identifier.encode("ascii")
        value_bytes = value.encode("ascii")
        name_op = {"op": OP_NAME_UPDATE, "name": identifier_bytes, "value": value_bytes}
        memo = ("Renew: " if renew else "Update: ") + format_name_identifier(identifier_bytes)

        if destination is None:
            request = await self.add_request(None, memo=memo, wallet=wallet)
            destination = request['address']

        final_outputs = []
        for o_address, o_amount in outputs:
            o_address = self._resolver(o_address, wallet)
            amount_sat = satoshis(o_amount)
            final_outputs.append(PartialTxOutput.from_address_and_value(o_address, amount_sat))
        destination = self._resolver(destination, wallet)
        amount_sat = satoshis(amount)
        name_output = PartialTxOutput.from_address_and_value(destination, amount_sat)
        name_output.add_name_op(name_op)
        final_outputs.append(name_output)

        tx = wallet.create_transaction(
            final_outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            unsigned=unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime,
            name_input_identifiers=[identifier_bytes])
        return tx.serialize()

    @command('wpn')
    async def name_autoregister(self, identifier, value="", destination=None, amount=0.0, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None, nocheck=False, rbf=None, password=None, locktime=None, allow_existing=False, wallet: Abstract_Wallet = None):
        """Creates a name_new transaction, broadcasts it, creates a corresponding name_firstupdate transaction, and queues it. """

        # Validate the value before we try to pre-register the name.  That way,
        # if the value is invalid, we'll be able to cancel the registration
        # without losing money in fees.
        validate_value_length(value)

        # TODO: Don't hardcode the 0.005 name_firstupdate fee
        new_result = await self.name_new(identifier,
                                   amount=amount+0.005,
                                   fee=fee,
                                   feerate=feerate,
                                   from_addr=from_addr,
                                   from_coins=from_coins,
                                   change_addr=change_addr,
                                   nocheck=nocheck,
                                   rbf=rbf,
                                   password=password,
                                   locktime=locktime,
                                   allow_existing=allow_existing,
                                   wallet=wallet)
        new_txid = new_result["txid"]
        new_rand = new_result["rand"]
        new_tx = new_result["tx"]

        # We add the name_new transaction to the wallet explicitly because
        # otherwise, the wallet will only learn about the name_new once the
        # ElectrumX server sends us a copy of the transaction, which is several
        # seconds later, which will cause the wallet to fail to spend the
        # name_new when we immediately create the name_firstupdate.
        status = await self.addtransaction(new_tx, wallet=wallet)
        if not status:
            raise Exception("Error adding name pre-registration to wallet")

        for o in Transaction(new_tx).outputs():
            if o.name_op is not None:
                new_addr = o.address
                break

        try:
            firstupdate_tx = await self.name_firstupdate(identifier,
                                                       new_rand,
                                                       new_txid,
                                                       value=value,
                                                       destination=destination,
                                                       amount=amount,
                                                       fee=fee,
                                                       feerate=feerate,
                                                       from_addr=new_addr,
                                                       change_addr=change_addr,
                                                       nocheck=nocheck,
                                                       rbf=rbf,
                                                       password=password,
                                                       locktime=locktime,
                                                       allow_early=True,
                                                       wallet=wallet)
            await self.queuetransaction(firstupdate_tx, 12, trigger_txid=new_txid, wallet=wallet)
        except Exception as e:
            await self.removelocaltx(new_txid, wallet=wallet)
            raise e

        await self.broadcast(new_tx)

    @command('w')
    async def onchain_history(self, year=None, show_addresses=False, show_fiat=False, wallet: Abstract_Wallet = None):
        """Wallet onchain history. Returns the transaction history of your wallet."""
        kwargs = {
            'show_addresses': show_addresses,
        }
        if year:
            import time
            start_date = datetime.datetime(year, 1, 1)
            end_date = datetime.datetime(year+1, 1, 1)
            kwargs['from_timestamp'] = time.mktime(start_date.timetuple())
            kwargs['to_timestamp'] = time.mktime(end_date.timetuple())
        if show_fiat:
            from .exchange_rate import FxThread
            fx = FxThread(self.config, None)
            kwargs['fx'] = fx
        return json_normalize(wallet.get_detailed_history(**kwargs))

    @command('w')
    async def init_lightning(self, wallet: Abstract_Wallet = None):
        """Enable lightning payments"""
        wallet.init_lightning()
        return "Lightning keys have been created."

    @command('w')
    async def remove_lightning(self, wallet: Abstract_Wallet = None):
        """Disable lightning payments"""
        wallet.remove_lightning()

    @command('w')
    async def lightning_history(self, show_fiat=False, wallet: Abstract_Wallet = None):
        """ lightning history """
        lightning_history = wallet.lnworker.get_history() if wallet.lnworker else []
        return json_normalize(lightning_history)

    @command('w')
    async def setlabel(self, key, label, wallet: Abstract_Wallet = None):
        """Assign a label to an item. Item may be a namecoin address or a
        transaction ID"""
        wallet.set_label(key, label)

    @command('w')
    async def listcontacts(self, wallet: Abstract_Wallet = None):
        """Show your list of contacts"""
        return wallet.contacts

    @command('w')
    async def getalias(self, key, wallet: Abstract_Wallet = None):
        """Retrieve alias. Lookup in your list of contacts, and for an OpenAlias DNS record."""
        return wallet.contacts.resolve(key)

    @command('w')
    async def searchcontacts(self, query, wallet: Abstract_Wallet = None):
        """Search through contacts, return matching entries. """
        results = {}
        for key, value in wallet.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    @command('w')
    async def listaddresses(self, receiving=False, change=False, labels=False, frozen=False, unused=False, funded=False, balance=False, wallet: Abstract_Wallet = None):
        """List wallet addresses. Returns the list of all addresses in your wallet. Use optional arguments to filter the results."""
        out = []
        for addr in wallet.get_addresses():
            if frozen and not wallet.is_frozen_address(addr):
                continue
            if receiving and wallet.is_change(addr):
                continue
            if change and not wallet.is_change(addr):
                continue
            if unused and wallet.is_used(addr):
                continue
            if funded and wallet.is_empty(addr):
                continue
            item = addr
            if labels or balance:
                item = (item,)
            if balance:
                item += (format_satoshis(sum(wallet.get_addr_balance(addr))),)
            if labels:
                item += (repr(wallet.labels.get(addr, '')),)
            out.append(item)
        return out

    @command('n')
    async def gettransaction(self, txid, wallet: Abstract_Wallet = None):
        """Retrieve a transaction. """
        tx = None
        if wallet:
            tx = wallet.db.get_transaction(txid)
        if tx is None:
            raw = await self.network.get_transaction(txid)
            if raw:
                tx = Transaction(raw)
            else:
                raise Exception("Unknown transaction")
        if tx.txid() != txid:
            raise Exception("Mismatching txid")
        return tx.serialize()

    @command('')
    async def encrypt(self, pubkey, message) -> str:
        """Encrypt a message with a public key. Use quotes if the message contains whitespaces."""
        if not is_hex_str(pubkey):
            raise Exception(f"pubkey must be a hex string instead of {repr(pubkey)}")
        try:
            message = to_bytes(message)
        except TypeError:
            raise Exception(f"message must be a string-like object instead of {repr(message)}")
        public_key = ecc.ECPubkey(bfh(pubkey))
        encrypted = public_key.encrypt_message(message)
        return encrypted.decode('utf-8')

    @command('wp')
    async def decrypt(self, pubkey, encrypted, password=None, wallet: Abstract_Wallet = None) -> str:
        """Decrypt a message encrypted with a public key."""
        if not is_hex_str(pubkey):
            raise Exception(f"pubkey must be a hex string instead of {repr(pubkey)}")
        if not isinstance(encrypted, (str, bytes, bytearray)):
            raise Exception(f"encrypted must be a string-like object instead of {repr(encrypted)}")
        decrypted = wallet.decrypt_message(pubkey, encrypted, password)
        return decrypted.decode('utf-8')

    @command('w')
    async def getrequest(self, key, wallet: Abstract_Wallet = None):
        """Return a payment request"""
        r = wallet.get_request(key)
        if not r:
            raise Exception("Request not found")
        return wallet.export_request(r)

    #@command('w')
    #async def ackrequest(self, serialized):
    #    """<Not implemented>"""
    #    pass

    @command('w')
    async def list_requests(self, pending=False, expired=False, paid=False, wallet: Abstract_Wallet = None):
        """List the payment requests you made."""
        if pending:
            f = PR_UNPAID
        elif expired:
            f = PR_EXPIRED
        elif paid:
            f = PR_PAID
        else:
            f = None
        out = wallet.get_sorted_requests()
        if f is not None:
            out = list(filter(lambda x: x.status==f, out))
        return [wallet.export_request(x) for x in out]

    @command('w')
    async def createnewaddress(self, wallet: Abstract_Wallet = None):
        """Create a new receiving address, beyond the gap limit of the wallet"""
        return wallet.create_new_address(False)

    @command('w')
    async def changegaplimit(self, new_limit, iknowwhatimdoing=False, wallet: Abstract_Wallet = None):
        """Change the gap limit of the wallet."""
        if not iknowwhatimdoing:
            raise Exception("WARNING: Are you SURE you want to change the gap limit?\n"
                            "It makes recovering your wallet from seed difficult!\n"
                            "Please do your research and make sure you understand the implications.\n"
                            "Typically only merchants and power users might want to do this.\n"
                            "To proceed, try again, with the --iknowwhatimdoing option.")
        if not isinstance(wallet, Deterministic_Wallet):
            raise Exception("This wallet is not deterministic.")
        return wallet.change_gap_limit(new_limit)

    @command('wn')
    async def getminacceptablegap(self, wallet: Abstract_Wallet = None):
        """Returns the minimum value for gap limit that would be sufficient to discover all
        known addresses in the wallet.
        """
        if not isinstance(wallet, Deterministic_Wallet):
            raise Exception("This wallet is not deterministic.")
        if not wallet.is_up_to_date():
            raise NotSynchronizedException("Wallet not fully synchronized.")
        return wallet.min_acceptable_gap()

    @command('w')
    async def getunusedaddress(self, wallet: Abstract_Wallet = None):
        """Returns the first unused address of the wallet, or None if all addresses are used.
        An address is considered as used if it has received a transaction, or if it is used in a payment request."""
        return wallet.get_unused_address()

    @command('w')
    async def add_request(self, amount, memo='', expiration=3600, force=False, wallet: Abstract_Wallet = None):
        """Create a payment request, using the first unused address of the wallet.
        The address will be considered as used after this operation.
        If no payment is received, the address will be considered as unused if the payment request is deleted from the wallet."""
        addr = wallet.get_unused_address()
        if addr is None:
            if force:
                addr = wallet.create_new_address(False)
            else:
                return False
        amount = satoshis(amount)
        expiration = int(expiration) if expiration else None
        req = wallet.make_payment_request(addr, amount, memo, expiration)
        wallet.add_payment_request(req)
        return wallet.export_request(req)

    @command('wn')
    async def add_lightning_request(self, amount, memo='', expiration=3600, wallet: Abstract_Wallet = None):
        amount_sat = int(satoshis(amount))
        key = await wallet.lnworker._add_request_coro(amount_sat, memo, expiration)
        return wallet.get_formatted_request(key)

    @command('w')
    async def addtransaction(self, tx, wallet: Abstract_Wallet = None):
        """ Add a transaction to the wallet history """
        tx = Transaction(tx)
        if not wallet.add_transaction(tx):
            return False
        wallet.save_db()
        return tx.txid()

    @command('w')
    async def queuetransaction(self, tx, trigger_depth, trigger_txid = None, trigger_name = None, wallet: Abstract_Wallet = None):
        """ Queue a transaction for later broadcast """
        if trigger_txid is None and trigger_name is None:
            raise Exception("You must specify exactly one of trigger_txid or trigger_name.")
        if trigger_txid is not None and trigger_name is not None:
            raise Exception("You must specify exactly one of trigger_txid or trigger_name.")

        txid = Transaction(tx).txid()
        # TODO: handle non-ASCII trigger_name
        send_when = {
            "txid": trigger_txid,
            "name": trigger_name,
            "name_encoding": "ascii",
            "confirmations": trigger_depth,
        }
        queue_item = {
            "tx": tx,
            "sendWhen": send_when
        }
        if not wallet.queue_transaction(txid, queue_item):
            return False
        wallet.save_db()
        return txid

    @command('wn')
    async def updatequeuedtransactions(self, wallet: Abstract_Wallet = None):
        errors = {}

        to_unqueue = []

        for txid in wallet.db.queued_transactions:
            queue_item = wallet.db.queued_transactions[txid]
            send_when = queue_item["sendWhen"]

            trigger_txid = send_when["txid"]
            trigger_name = send_when["name"]
            trigger_depth = send_when["confirmations"]

            chain_height = self.network.get_local_height()

            current_depth = 0

            if trigger_name is not None:
                # TODO: handle non-ASCII trigger_name
                try:
                    current_height = await self.name_show(trigger_name)["height"]
                    current_depth = chain_height - current_height + 1
                except NameNotFoundError:
                    current_depth = constants.net.NAME_EXPIRATION
                except Exception:
                    continue

            if trigger_txid is not None:
                current_depth = wallet.get_tx_height(trigger_txid).conf

            if current_depth >= trigger_depth:
                tx = queue_item["tx"]
                try:
                    await self.broadcast(tx)
                except Exception as e:
                    errors[txid] = str(e)

                to_unqueue.append(txid)

        for txid in to_unqueue:
            wallet.unqueue_transaction(txid)
        wallet.save_db()

        success = (errors == {})
        return success, errors

    @command('wp')
    async def signrequest(self, address, password=None, wallet: Abstract_Wallet = None):
        "Sign payment request with an OpenAlias"
        alias = self.config.get('alias')
        if not alias:
            raise Exception('No alias in your configuration')
        alias_addr = wallet.contacts.resolve(alias)['address']
        wallet.sign_payment_request(address, alias, alias_addr, password)

    @command('w')
    async def rmrequest(self, address, wallet: Abstract_Wallet = None):
        """Remove a payment request"""
        return wallet.remove_payment_request(address)

    @command('w')
    async def clear_requests(self, wallet: Abstract_Wallet = None):
        """Remove all payment requests"""
        for k in list(wallet.receive_requests.keys()):
            wallet.remove_payment_request(k)

    @command('w')
    async def clear_invoices(self, wallet: Abstract_Wallet = None):
        """Remove all invoices"""
        wallet.clear_invoices()
        return True

    @command('n')
    async def notify(self, address: str, URL: Optional[str]):
        """Watch an address. Every time the address changes, a http POST is sent to the URL.
        Call with an empty URL to stop watching an address.
        """
        if not hasattr(self, "_notifier"):
            self._notifier = Notifier(self.network)
        if URL:
            await self._notifier.start_watching_addr(address, URL)
        else:
            await self._notifier.stop_watching_addr(address)
        return True

    @command('wn')
    async def is_synchronized(self, wallet: Abstract_Wallet = None):
        """ return wallet synchronization status """
        return wallet.is_up_to_date()

    @command('n')
    async def getfeerate(self, fee_method=None, fee_level=None):
        """Return current suggested fee rate (in sat/kvByte), according to config
        settings or supplied parameters.
        """
        if fee_method is None:
            dyn, mempool = None, None
        elif fee_method.lower() == 'static':
            dyn, mempool = False, False
        elif fee_method.lower() == 'eta':
            dyn, mempool = True, False
        elif fee_method.lower() == 'mempool':
            dyn, mempool = True, True
        else:
            raise Exception('Invalid fee estimation method: {}'.format(fee_method))
        if fee_level is not None:
            fee_level = Decimal(fee_level)
        return self.config.fee_per_kb(dyn=dyn, mempool=mempool, fee_level=fee_level)

    @command('n')
    async def name_show(self, identifier, wallet: Abstract_Wallet = None):
        # TODO: support non-ASCII encodings
        identifier_bytes = identifier.encode("ascii")
        sh = name_identifier_to_scripthash(identifier_bytes)

        txs = await self.network.get_history_for_scripthash(sh)

        # Check the blockchain height (local and server chains)
        local_chain_height = self.network.get_local_height()
        server_chain_height = self.network.get_server_height()
        max_chain_height = max(local_chain_height, server_chain_height)

        # Pick the most recent name op that's [12, 36000) confirmations.
        # Expiration is calculated using max of local and server height.
        # Verification depth is calculated using local height.
        # If a transaction has under 12 local confirmations, then we check
        # whether it also has under 18 server confirmations.  If so, then we
        # just skip it and look for an older transaction.  If it has more than
        # 18 server confirmations but under 12 local confirmations, then we're
        # probably still syncing, and we error.
        unexpired_height = max_chain_height - constants.net.NAME_EXPIRATION + 1
        unverified_height = local_chain_height - 12 + 1
        unmined_height = max_chain_height - 18 + 1

        tx_best = None
        expired_tx_exists = False
        expired_tx_height = None
        unmined_tx_exists = False
        unmined_tx_height = None
        for tx_candidate in txs[::-1]:
            if tx_candidate["height"] < unexpired_height:
                # Transaction is expired.  Skip.
                expired_tx_exists = True
                # We want to log the *latest* expired height.  We're iterating
                # in reverse chronological order, so we only take the first one
                # we see.
                if expired_tx_height is None:
                    expired_tx_height = tx_candidate["height"]
                continue
            if tx_candidate["height"] > unverified_height:
                # Transaction doesn't have enough verified depth.  What we do
                # here depends on whether it's due to lack of mining or because
                # we're still syncing.

                if tx_candidate["height"] > unmined_height:
                    # Transaction is new; skip in favor of an older one.
                    unmined_tx_exists = True
                    # We want to log the *earliest* unconfirmed height.  We're
                    # iterating in reverse chronological order, so we take the
                    # last one we see.
                    unmined_tx_height = tx_candidate["height"]
                    continue

                # We can't verify the transaction because we're still syncing,
                # but we have reason to believe that previous transactions will
                # be stale.  So we have to error.
                raise NotSynchronizedException('The blockchain is still syncing (latest purported transaction height {}, local chain height {}, server chain height {})'.format(tx_candidate["height"], local_chain_height, server_chain_height))

            tx_best = tx_candidate
            break

        if unmined_tx_exists:
            raise NameUnconfirmedError('Name is purportedly unconfirmed (registration height {}, latest verified height {})'.format(unmined_tx_height, unverified_height))
        if expired_tx_exists:
            raise NameExpiredError("Name is purportedly expired (latest renewal height {}, latest unexpired height {})".format(expired_tx_height, unexpired_height))
        if tx_best is None:
            raise NameNeverExistedError("Name purportedly never existed")
        txid = tx_best["tx_hash"]
        height = tx_best["height"]

        # The height is now verified to be safe.

        # (from verifier._request_proofs) if it's in the checkpoint region, we still might not have the header
        header = self.network.blockchain().read_header(height)
        if header is None:
            if height < constants.net.max_checkpoint():
                await self.network.request_chunk(height, None)

        # (from verifier._request_and_verify_single_proof)
        merkle = await self.network.get_merkle_for_transaction(txid, height)
        if height != merkle.get('block_height'):
            raise Exception('requested height {} differs from received height {} for txid {}'
                            .format(height, merkle.get('block_height'), txid))
        pos = merkle.get('pos')
        merkle_branch = merkle.get('merkle')
        async def wait_for_header():
            # we need to wait if header sync/reorg is still ongoing, hence lock:
            async with self.network.bhi_lock:
                return self.network.blockchain().read_header(height)
        header = await wait_for_header()
        verify_tx_is_in_block(txid, merkle_branch, pos, header, height)

        # The txid is now verified to come from a safe height in the blockchain.

        if wallet and txid in wallet.db.transactions:
            tx = wallet.db.transactions[txid]
        else:
            raw = await self.network.get_transaction(txid)
            if raw:
                tx = Transaction(raw)
            else:
                raise Exception("Unknown transaction (txid {})".format(txid))

        if tx.txid() != txid:
            raise Exception("txid mismatch ({} vs {})".format(tx.txid(), txid))

        # the tx is now verified to come from a safe height in the blockchain

        for idx, o in enumerate(tx.outputs()):
            if o.name_op is not None:
                if "name" in o.name_op:
                    if o.name_op["name"] != identifier_bytes:
                        # Identifier mismatch.  This will definitely fail under
                        # current Namecoin consensus rules, but in a future
                        # hardfork there might be multiple name outputs, so we
                        # might as well future-proof and scan the other
                        # outputs.
                        continue

                    # the tx is now verified to represent the identifier at a
                    # safe height in the blockchain

                    is_mine = None
                    if wallet:
                        is_mine = wallet.is_mine(o.address)

                    return {
                        "name": o.name_op["name"].decode("ascii"),
                        "name_encoding": "ascii",
                        "value": o.name_op["value"].decode("ascii"),
                        "value_encoding": "ascii",
                        "txid": txid,
                        "vout": idx,
                        "address": o.address,
                        "height": height,
                        "expires_in": name_expires_in(height, local_chain_height),
                        "expired": False,
                        "ismine": is_mine,
                    }

        raise Exception("missing name op (txid {})".format(txid))

    @command('w')
    async def removelocaltx(self, txid, wallet: Abstract_Wallet = None):
        """Remove a 'local' transaction from the wallet, and its dependent
        transactions.
        """
        if not is_hash256_str(txid):
            raise Exception(f"{repr(txid)} is not a txid")
        height = wallet.get_tx_height(txid).height
        to_delete = {txid}
        if height != TX_HEIGHT_LOCAL:
            raise Exception(f'Only local transactions can be removed. '
                            f'This tx has height: {height} != {TX_HEIGHT_LOCAL}')
        to_delete |= wallet.get_depending_transactions(txid)
        for tx_hash in to_delete:
            wallet.remove_transaction(tx_hash)
        wallet.save_db()

    @command('wn')
    async def get_tx_status(self, txid, wallet: Abstract_Wallet = None):
        """Returns some information regarding the tx. For now, only confirmations.
        The transaction must be related to the wallet.
        """
        if not is_hash256_str(txid):
            raise Exception(f"{repr(txid)} is not a txid")
        if not wallet.db.get_transaction(txid):
            raise Exception("Transaction not in wallet.")
        return {
            "confirmations": wallet.get_tx_height(txid).conf,
        }

    @command('')
    async def help(self):
        # for the python console
        return sorted(known_commands.keys())

    # lightning network commands
    @command('wn')
    async def add_peer(self, connection_string, timeout=20, gossip=False, wallet: Abstract_Wallet = None):
        lnworker = self.network.lngossip if gossip else wallet.lnworker
        await lnworker.add_peer(connection_string)
        return True

    @command('wn')
    async def list_peers(self, gossip=False, wallet: Abstract_Wallet = None):
        lnworker = self.network.lngossip if gossip else wallet.lnworker
        return [{
            'node_id':p.pubkey.hex(),
            'address':p.transport.name(),
            'initialized':p.is_initialized(),
            'features': str(LnFeatures(p.features)),
            'channels': [c.funding_outpoint.to_str() for c in p.channels.values()],
        } for p in lnworker.peers.values()]

    @command('wpn')
    async def open_channel(self, connection_string, amount, push_amount=0, password=None, wallet: Abstract_Wallet = None):
        funding_sat = satoshis(amount)
        push_sat = satoshis(push_amount)
        dummy_output = PartialTxOutput.from_address_and_value(ln_dummy_address(), funding_sat)
        funding_tx = wallet.mktx(outputs = [dummy_output], rbf=False, sign=False, nonlocal_only=True)
        chan, funding_tx = await wallet.lnworker._open_channel_coroutine(connect_str=connection_string,
                                                                         funding_tx=funding_tx,
                                                                         funding_sat=funding_sat,
                                                                         push_sat=push_sat,
                                                                         password=password)
        return chan.funding_outpoint.to_str()

    @command('')
    async def decode_invoice(self, invoice: str):
        invoice = LNInvoice.from_bech32(invoice)
        return invoice.to_debug_json()

    @command('wn')
    async def lnpay(self, invoice, attempts=1, timeout=30, wallet: Abstract_Wallet = None):
        lnworker = wallet.lnworker
        lnaddr = lnworker._check_invoice(invoice)
        payment_hash = lnaddr.paymenthash
        wallet.save_invoice(LNInvoice.from_bech32(invoice))
        success, log = await lnworker._pay(invoice, attempts=attempts)
        return {
            'payment_hash': payment_hash.hex(),
            'success': success,
            'preimage': lnworker.get_preimage(payment_hash).hex() if success else None,
            'log': [x.formatted_tuple() for x in log]
        }

    @command('w')
    async def nodeid(self, wallet: Abstract_Wallet = None):
        listen_addr = self.config.get('lightning_listen')
        return bh2u(wallet.lnworker.node_keypair.pubkey) + (('@' + listen_addr) if listen_addr else '')

    @command('w')
    async def list_channels(self, wallet: Abstract_Wallet = None):
        # we output the funding_outpoint instead of the channel_id because lnd uses channel_point (funding outpoint) to identify channels
        from .lnutil import LOCAL, REMOTE, format_short_channel_id
        l = list(wallet.lnworker.channels.items())
        return [
            {
                'short_channel_id': format_short_channel_id(chan.short_channel_id) if chan.short_channel_id else None,
                'channel_id': bh2u(chan.channel_id),
                'channel_point': chan.funding_outpoint.to_str(),
                'state': chan.get_state().name,
                'peer_state': chan.peer_state.name,
                'remote_pubkey': bh2u(chan.node_id),
                'local_balance': chan.balance(LOCAL)//1000,
                'remote_balance': chan.balance(REMOTE)//1000,
                'local_reserve': chan.config[REMOTE].reserve_sat, # their config has our reserve
                'remote_reserve': chan.config[LOCAL].reserve_sat,
                'local_unsettled_sent': chan.balance_tied_up_in_htlcs_by_direction(LOCAL, direction=SENT) // 1000,
                'remote_unsettled_sent': chan.balance_tied_up_in_htlcs_by_direction(REMOTE, direction=SENT) // 1000,
            } for channel_id, chan in l
        ]

    @command('wn')
    async def dumpgraph(self, wallet: Abstract_Wallet = None):
        return list(map(bh2u, wallet.lnworker.channel_db.nodes.keys()))

    @command('n')
    async def inject_fees(self, fees):
        import ast
        self.network.config.fee_estimates = ast.literal_eval(fees)
        self.network.notify('fee')

    @command('wn')
    async def enable_htlc_settle(self, b: bool, wallet: Abstract_Wallet = None):
        e = wallet.lnworker.enable_htlc_settle
        e.set() if b else e.clear()

    @command('n')
    async def clear_ln_blacklist(self):
        self.network.path_finder.blacklist.clear()

    @command('w')
    async def list_invoices(self, wallet: Abstract_Wallet = None):
        l = wallet.get_invoices()
        return [wallet.export_invoice(x) for x in l]

    @command('wn')
    async def close_channel(self, channel_point, force=False, wallet: Abstract_Wallet = None):
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        coro = wallet.lnworker.force_close_channel(chan_id) if force else wallet.lnworker.close_channel(chan_id)
        return await coro

    @command('w')
    async def export_channel_backup(self, channel_point, wallet: Abstract_Wallet = None):
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        return wallet.lnworker.export_channel_backup(chan_id)

    @command('w')
    async def import_channel_backup(self, encrypted, wallet: Abstract_Wallet = None):
        return wallet.lnbackups.import_channel_backup(encrypted)

    @command('wn')
    async def get_channel_ctx(self, channel_point, iknowwhatimdoing=False, wallet: Abstract_Wallet = None):
        """ return the current commitment transaction of a channel """
        if not iknowwhatimdoing:
            raise Exception("WARNING: this command is potentially unsafe.\n"
                            "To proceed, try again, with the --iknowwhatimdoing option.")
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        chan = wallet.lnworker.channels[chan_id]
        tx = chan.force_close_tx()
        return tx.serialize()

    @command('wn')
    async def get_watchtower_ctn(self, channel_point, wallet: Abstract_Wallet = None):
        """ return the local watchtower's ctn of channel. used in regtests """
        return await self.network.local_watchtower.sweepstore.get_ctn(channel_point, None)

    @command('wnp')
    async def normal_swap(self, onchain_amount, lightning_amount, password=None, wallet: Abstract_Wallet = None):
        """
        Normal submarine swap: send on-chain BTC, receive on Lightning
        Note that your funds will be locked for 24h if you do not have enough incoming capacity.
        """
        sm = wallet.lnworker.swap_manager
        if lightning_amount == 'dryrun':
            await sm.get_pairs()
            onchain_amount_sat = satoshis(onchain_amount)
            lightning_amount_sat = sm.get_recv_amount(onchain_amount_sat, is_reverse=False)
            txid = None
        elif onchain_amount == 'dryrun':
            await sm.get_pairs()
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = sm.get_send_amount(lightning_amount_sat, is_reverse=False)
            txid = None
        else:
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = satoshis(onchain_amount)
            txid = await wallet.lnworker.swap_manager.normal_swap(lightning_amount_sat, onchain_amount_sat, password)
        return {
            'txid': txid,
            'lightning_amount': format_satoshis(lightning_amount_sat),
            'onchain_amount': format_satoshis(onchain_amount_sat),
        }

    @command('wn')
    async def reverse_swap(self, lightning_amount, onchain_amount, wallet: Abstract_Wallet = None):
        """Reverse submarine swap: send on Lightning, receive on-chain
        """
        sm = wallet.lnworker.swap_manager
        if onchain_amount == 'dryrun':
            await sm.get_pairs()
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = sm.get_recv_amount(lightning_amount_sat, is_reverse=True)
            success = None
        elif lightning_amount == 'dryrun':
            await sm.get_pairs()
            onchain_amount_sat = satoshis(onchain_amount)
            lightning_amount_sat = sm.get_send_amount(onchain_amount_sat, is_reverse=True)
            success = None
        else:
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = satoshis(onchain_amount)
            success = await wallet.lnworker.swap_manager.reverse_swap(lightning_amount_sat, onchain_amount_sat)
        return {
            'success': success,
            'lightning_amount': format_satoshis(lightning_amount_sat),
            'onchain_amount': format_satoshis(onchain_amount_sat),
        }


def eval_bool(x: str) -> bool:
    if x == 'false': return False
    if x == 'true': return True
    try:
        return bool(ast.literal_eval(x))
    except:
        return bool(x)

param_descriptions = {
    'privkey': 'Private key. Type \'?\' to get a prompt.',
    'destination': 'Namecoin address, contact or alias',
    'address': 'Namecoin address',
    'seed': 'Seed phrase',
    'txid': 'Transaction ID',
    'pos': 'Position',
    'height': 'Block height',
    'tx': 'Serialized transaction (hexadecimal)',
    'key': 'Variable name',
    'pubkey': 'Public key',
    'message': 'Clear text message. Use quotes if it contains spaces.',
    'encrypted': 'Encrypted message',
    'amount': 'Amount to be sent (in RADC). Type \'!\' to send the maximum available.',
    'requested_amount': 'Requested amount (in RADC).',
    'outputs': 'list of ["address", amount]',
    'redeem_script': 'redeem script (hexadecimal)',
    'lightning_amount': "Amount sent or received in a submarine swap. Set it to 'dryrun' to receive a value",
    'onchain_amount': "Amount sent or received in a submarine swap. Set it to 'dryrun' to receive a value",
}

command_options = {
    'password':    ("-W", "Password"),
    'new_password':(None, "New Password"),
    'encrypt_file':(None, "Whether the file on disk should be encrypted with the provided password"),
    'receiving':   (None, "Show only receiving addresses"),
    'change':      (None, "Show only change addresses"),
    'frozen':      (None, "Show only frozen addresses"),
    'unused':      (None, "Show only unused addresses"),
    'funded':      (None, "Show only funded addresses"),
    'balance':     ("-b", "Show the balances of listed addresses"),
    'labels':      ("-l", "Show the labels of listed addresses"),
    'nocheck':     (None, "Do not verify aliases"),
    'imax':        (None, "Maximum number of inputs"),
    'fee':         ("-f", "Transaction fee (absolute, in RADC)"),
    'feerate':     (None, "Transaction fee rate (in noise/byte)"),
    'from_addr':   ("-F", "Source address (must be a wallet address; use sweep to spend from non-wallet address)."),
    'from_coins':  (None, "Source coins (must be in wallet; use sweep to spend from non-wallet address)."),
    'change_addr': ("-c", "Change address. Default is a spare address, or the source address if it's not in the wallet"),
    'nbits':       (None, "Number of bits of entropy"),
    'seed_type':   (None, "The type of seed to create, e.g. 'standard' or 'segwit'"),
    'language':    ("-L", "Default language for wordlist"),
    'passphrase':  (None, "Seed extension"),
    'privkey':     (None, "Private key. Set to '?' to get a prompt."),
    'unsigned':    ("-u", "Do not sign transaction"),
    'rbf':         (None, "Whether to signal opt-in Replace-By-Fee in the transaction (true/false)"),
    'locktime':    (None, "Set locktime block number"),
    'domain':      ("-D", "List of addresses"),
    'memo':        ("-m", "Description of the request"),
    'expiration':  (None, "Time in seconds"),
    'attempts':    (None, "Number of payment attempts"),
    'timeout':     (None, "Timeout in seconds"),
    'force':       (None, "Create new address beyond gap limit, if no more addresses are available."),
    'pending':     (None, "Show only pending requests."),
    'push_amount': (None, 'Push initial amount (in RADC)'),
    'expired':     (None, "Show only expired requests."),
    'paid':        (None, "Show only paid requests."),
    'show_addresses': (None, "Show input and output addresses"),
    'show_fiat':   (None, "Show fiat value of transactions"),
    'show_fees':   (None, "Show miner fees paid by transactions"),
    'year':        (None, "Show history for a given year"),
    'fee_method':  (None, "Fee estimation method to use"),
    'fee_level':   (None, "Float between 0.0 and 1.0, representing fee slider position"),
    'from_height': (None, "Only show transactions that confirmed after given block height"),
    'to_height':   (None, "Only show transactions that confirmed before given block height"),
    'iknowwhatimdoing': (None, "Acknowledge that I understand the full implications of what I am about to do"),
    'gossip':      (None, "Apply command to gossip node instead of wallet"),
    'destination': (None, "Namecoin address, contact or alias"),
    'amount':      (None, "Amount to be sent (in RADC). Type \'!\' to send the maximum available."),
    'outputs':     (None, "Currency outputs to add to a transaction in addition to a name operation."),
    'allow_existing': (None, "Allow pre-registering a name that already is registered.  Your registration fee will be forfeited until you can register the name after it expires."),
    'allow_early': (None, "Allow submitting a name registration while its pre-registration is still pending.  This increases the risk of an attacker stealing your name registration."),
    'identifier':  (None, "The requested name identifier"),
    'value':       (None, "The value to assign to the name"),
    'name_encoding': (None, "Encoding for the name identifier ('ascii' or 'hex')"),
    'value_encoding': (None, "Encoding for the name value ('ascii' or 'hex')"),
    'rand':        (None, "Salt for the name pre-registration commitment (returned by name_new; you can usually omit this)"),
    'name_new_txid':(None, "Transaction ID for the name pre-registration (returned by name_new; you can usually omit this)"),
    'trigger_txid':(None, "Broadcast the transaction when this txid reaches the specified number of confirmations"),
    'trigger_name':(None, "Broadcast the transaction when this name reaches the specified number of confirmations"),
}


# don't use floats because of rounding errors
from .transaction import convert_raw_tx_to_hex
json_loads = lambda x: json.loads(x, parse_float=lambda x: str(Decimal(x)))
arg_types = {
    'num': int,
    'nbits': int,
    'imax': int,
    'year': int,
    'from_height': int,
    'to_height': int,
    'tx': convert_raw_tx_to_hex,
    'pubkeys': json_loads,
    'jsontx': json_loads,
    'inputs': json_loads,
    'outputs': json_loads,
    'fee': lambda x: str(Decimal(x)) if x is not None else None,
    'amount': lambda x: str(Decimal(x)) if x != '!' else '!',
    'locktime': int,
    'fee_method': str,
    'fee_level': json_loads,
    'encrypt_file': eval_bool,
    'rbf': eval_bool,
    'timeout': float,
    'attempts': int,
}

config_variables = {

    'addrequest': {
        'ssl_privkey': 'Path to your SSL private key, needed to sign the request.',
        'ssl_chain': 'Chain of SSL certificates, needed for signed requests. Put your certificate at the top and the root CA at the end',
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of namecoin: URIs. Example: \"(\'file:///var/www/\',\'https://www.namecoin.org/\')\"',
    },
    'listrequests':{
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of namecoin: URIs. Example: \"(\'file:///var/www/\',\'https://www.namecoin.org/\')\"',
    }
}

def set_default_subparser(self, name, args=None):
    """see http://stackoverflow.com/questions/5176691/argparse-how-to-specify-a-default-subcommand"""
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:  # global help if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)

argparse.ArgumentParser.set_default_subparser = set_default_subparser


# workaround https://bugs.python.org/issue23058
# see https://github.com/nickstenning/honcho/pull/121

def subparser_call(self, parser, namespace, values, option_string=None):
    from argparse import ArgumentError, SUPPRESS, _UNRECOGNIZED_ARGS_ATTR
    parser_name = values[0]
    arg_strings = values[1:]
    # set the parser name if requested
    if self.dest is not SUPPRESS:
        setattr(namespace, self.dest, parser_name)
    # select the parser
    try:
        parser = self._name_parser_map[parser_name]
    except KeyError:
        tup = parser_name, ', '.join(self._name_parser_map)
        msg = _('unknown parser {!r} (choices: {})').format(*tup)
        raise ArgumentError(self, msg)
    # parse all the remaining options into the namespace
    # store any unrecognized options on the object, so that the top
    # level parser can decide what to do with them
    namespace, arg_strings = parser.parse_known_args(arg_strings, namespace)
    if arg_strings:
        vars(namespace).setdefault(_UNRECOGNIZED_ARGS_ATTR, [])
        getattr(namespace, _UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)

argparse._SubParsersAction.__call__ = subparser_call


def add_network_options(parser):
    parser.add_argument("-f", "--serverfingerprint", dest="serverfingerprint", default=None, help="only allow connecting to servers with a matching SSL certificate SHA256 fingerprint." + " " +
                                                                                                  "To calculate this yourself: '$ openssl x509 -noout -fingerprint -sha256 -inform pem -in mycertfile.crt'. Enter as 64 hex chars.")
    parser.add_argument("-1", "--oneserver", action="store_true", dest="oneserver", default=None, help="connect to one server only")
    parser.add_argument("-s", "--server", dest="server", default=None, help="set server host:port:protocol, where protocol is either t (tcp) or s (ssl)")
    parser.add_argument("-p", "--proxy", dest="proxy", default=None, help="set proxy [type:]host[:port] (or 'none' to disable proxy), where type is socks4,socks5 or http")
    parser.add_argument("--noonion", action="store_true", dest="noonion", default=None, help="do not try to connect to onion servers")
    parser.add_argument("--skipmerklecheck", action="store_true", dest="skipmerklecheck", default=None, help="Tolerate invalid merkle proofs from server")

def add_global_options(parser):
    group = parser.add_argument_group('global options')
    group.add_argument("-v", dest="verbosity", help="Set verbosity (log levels)", default='')
    group.add_argument("-V", dest="verbosity_shortcuts", help="Set verbosity (shortcut-filter list)", default='')
    group.add_argument("-D", "--dir", dest="electrum_path", help="electrum-radc directory")
    group.add_argument("-P", "--portable", action="store_true", dest="portable", default=False, help="Use local 'electrum-radc_data' directory")
    group.add_argument("--testnet", action="store_true", dest="testnet", default=False, help="Use Testnet")
    group.add_argument("--regtest", action="store_true", dest="regtest", default=False, help="Use Regtest")
    group.add_argument("--simnet", action="store_true", dest="simnet", default=False, help="Use Simnet")
    group.add_argument("-o", "--offline", action="store_true", dest="offline", default=False, help="Run offline")

def add_wallet_option(parser):
    parser.add_argument("-w", "--wallet", dest="wallet_path", help="wallet path")
    parser.add_argument("--forgetconfig", action="store_true", dest="forget_config", default=False, help="Forget config on exit")

def get_parser():
    # create main parser
    parser = argparse.ArgumentParser(
        epilog="Run 'electrum-radc help <command>' to see the help for a command")
    add_global_options(parser)
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui', description="Run Electrum-RADC's Graphical User Interface.", help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="namecoin URI (or bip70 file)")
    parser_gui.add_argument("-g", "--gui", dest="gui", help="select graphical user interface", choices=['qt', 'kivy', 'text', 'stdio'])
    parser_gui.add_argument("-m", action="store_true", dest="hide_gui", default=False, help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest="language", default=None, help="default language used in GUI")
    parser_gui.add_argument("--daemon", action="store_true", dest="daemon", default=False, help="keep daemon running after GUI is closed")
    add_wallet_option(parser_gui)
    add_network_options(parser_gui)
    add_global_options(parser_gui)
    # daemon
    parser_daemon = subparsers.add_parser('daemon', help="Run Daemon")
    parser_daemon.add_argument("-d", "--detached", action="store_true", dest="detach", default=False, help="run daemon in detached mode")
    add_network_options(parser_daemon)
    add_global_options(parser_daemon)
    # commands
    for cmdname in sorted(known_commands.keys()):
        cmd = known_commands[cmdname]
        p = subparsers.add_parser(cmdname, help=cmd.help, description=cmd.description)
        for optname, default in zip(cmd.options, cmd.defaults):
            if optname in ['wallet_path', 'wallet']:
                add_wallet_option(p)
                continue
            a, help = command_options[optname]
            b = '--' + optname
            action = "store_true" if default is False else 'store'
            args = (a, b) if a else (b,)
            if action == 'store':
                _type = arg_types.get(optname, str)
                p.add_argument(*args, dest=optname, action=action, default=default, help=help, type=_type)
            else:
                p.add_argument(*args, dest=optname, action=action, default=default, help=help)
        add_global_options(p)

        for param in cmd.params:
            if param in ['wallet_path', 'wallet']:
                continue
            h = param_descriptions.get(param, '')
            _type = arg_types.get(param, str)
            p.add_argument(param, help=h, type=_type)

        cvh = config_variables.get(cmdname)
        if cvh:
            group = p.add_argument_group('configuration variables', '(set with setconfig/getconfig)')
            for k, v in cvh.items():
                group.add_argument(k, nargs='?', help=v)

    # 'gui' is the default command
    parser.set_default_subparser('gui')
    return parser
