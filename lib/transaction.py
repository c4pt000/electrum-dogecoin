#!/usr/bin/env python
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


# Note: The deserialization code originally comes from ABE.


import bitcoin
from bitcoin import *
from util import print_error
import time
import struct

#
# Workalike python implementation of Bitcoin's CDataStream class.
#
import struct
import StringIO
import mmap
import random

NO_SIGNATURE = 'ff'

class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """

class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, bytes):  # Initialize with string of bytes
        if self.input is None:
            self.input = bytes
        else:
            self.input += bytes

    def map_file(self, file, start):  # Initialize with bytes from file
        self.input = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        self.read_cursor = start

    def seek_file(self, position):
        self.read_cursor = position

    def close_file(self):
        self.input.close()

    def read_string(self):
        # Strings are encoded depending on length:
        # 0 to 252 :  1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            length = self.read_compact_size()
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return self.read_bytes(length)

    def write_string(self, string):
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor+length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return ''

    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int16(self): return self._read_num('<h')
    def read_uint16(self): return self._read_num('<H')
    def read_int32(self): return self._read_num('<i')
    def read_uint32(self): return self._read_num('<I')
    def read_int64(self): return self._read_num('<q')
    def read_uint64(self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
    def write_int16(self, val): return self._write_num('<h', val)
    def write_uint16(self, val): return self._write_num('<H', val)
    def write_int32(self, val): return self._write_num('<i', val)
    def write_uint32(self, val): return self._write_num('<I', val)
    def write_int64(self, val): return self._write_num('<q', val)
    def write_uint64(self, val): return self._write_num('<Q', val)

    def read_compact_size(self):
        size = ord(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num('<H')
        elif size == 254:
            size = self._read_num('<I')
        elif size == 255:
            size = self._read_num('<Q')
        return size

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(chr(size))
        elif size < 2**16:
            self.write('\xfd')
            self._write_num('<H', size)
        elif size < 2**32:
            self.write('\xfe')
            self._write_num('<I', size)
        elif size < 2**64:
            self.write('\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)

#
# enum-like type
# From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
#
import types, string, exceptions

class EnumException(exceptions.Exception):
    pass

class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = { }
        reverseLookup = { }
        i = 0
        uniqueNames = [ ]
        uniqueValues = [ ]
        for x in enumList:
            if type(x) == types.TupleType:
                x, i = x
            if type(x) != types.StringType:
                raise EnumException, "enum name is not a string: " + x
            if type(i) != types.IntType:
                raise EnumException, "enum value is not an integer: " + i
            if x in uniqueNames:
                raise EnumException, "enum name is not unique: " + x
            if i in uniqueValues:
                raise EnumException, "enum value is not unique for " + x
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup
    def __getattr__(self, attr):
        if not self.lookup.has_key(attr):
            raise AttributeError
        return self.lookup[attr]
    def whatis(self, value):
        return self.reverseLookup[value]


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')

# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]




def parse_redeemScript(bytes):
    dec = [ x for x in script_GetOp(bytes.decode('hex')) ]

    # 2 of 2
    match = [ opcodes.OP_2, opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4, opcodes.OP_2, opcodes.OP_CHECKMULTISIG ]
    if match_decoded(dec, match):
        pubkeys = [ dec[1][1].encode('hex'), dec[2][1].encode('hex') ]
        return 2, pubkeys

    # 2 of 3
    match = [ opcodes.OP_2, opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4, opcodes.OP_3, opcodes.OP_CHECKMULTISIG ]
    if match_decoded(dec, match):
        pubkeys = [ dec[1][1].encode('hex'), dec[2][1].encode('hex'), dec[3][1].encode('hex') ]
        return 2, pubkeys



opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1",76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_SINGLEBYTE_END", 0xF0),
    ("OP_DOUBLEBYTE_BEGIN", 0xF000),
    "OP_PUBKEY", "OP_PUBKEYHASH",
    ("OP_INVALIDOPCODE", 0xFFFF),
])


def script_GetOp(bytes):
    i = 0
    while i < len(bytes):
        vch = None
        opcode = ord(bytes[i])
        i += 1
        if opcode >= opcodes.OP_SINGLEBYTE_END:
            opcode <<= 8
            opcode |= ord(bytes[i])
            i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                nSize = ord(bytes[i])
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                (nSize,) = struct.unpack_from('<H', bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', bytes, i)
                i += 4
            vch = bytes[i:i+nSize]
            i += nSize

        yield (opcode, vch, i)


def script_GetOpName(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")


def decode_script(bytes):
    result = ''
    for (opcode, vch, i) in script_GetOp(bytes):
        if len(result) > 0: result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += "%d:"%(opcode,)
            result += short_hex(vch)
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False;
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4 and decoded[i][0]>0:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True


def parse_sig(x_sig):
    s = []
    for sig in x_sig:
        if sig[-2:] == '01':
            s.append(sig[:-2])
        else:
            assert sig == NO_SIGNATURE
            s.append(None)
    return s

def is_extended_pubkey(x_pubkey):
    return x_pubkey[0:2] in ['fe', 'ff']

def x_to_xpub(x_pubkey):
    if x_pubkey[0:2] == 'ff':
        from account import BIP32_Account
        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub



def parse_xpub(x_pubkey):
    if x_pubkey[0:2] in ['02','03','04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        from account import BIP32_Account
        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
        pubkey = BIP32_Account.derive_pubkey_from_xpub(xpub, s[0], s[1])
    elif x_pubkey[0:2] == 'fe':
        from account import OldAccount
        mpk, s = OldAccount.parse_xpubkey(x_pubkey)
        pubkey = OldAccount.get_pubkey_from_mpk(mpk.decode('hex'), s[0], s[1])
    elif x_pubkey[0:2] == 'fd':
        addrtype = ord(x_pubkey[2:4].decode('hex'))
        hash160 = x_pubkey[4:].decode('hex')
        pubkey = None
        address = hash_160_to_bc_address(hash160, addrtype)
    else:
        raise BaseException("Cannnot parse pubkey")
    if pubkey:
        address = public_key_to_bc_address(pubkey.decode('hex'))
    return pubkey, address


def parse_scriptSig(d, bytes):
    try:
        decoded = [ x for x in script_GetOp(bytes) ]
    except Exception:
        # coinbase transactions raise an exception
        print_error("cannot find address in input script", bytes.encode('hex'))
        return

    # payto_pubkey
    match = [ opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = decoded[0][1].encode('hex')
        d['address'] = "(pubkey)"
        d['signatures'] = [sig]
        d['num_sig'] = 1
        d['x_pubkeys'] = ["(pubkey)"]
        d['pubkeys'] = ["(pubkey)"]
        return

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (65 bytes) onto the stack:
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = decoded[0][1].encode('hex')
        x_pubkey = decoded[1][1].encode('hex')
        try:
            signatures = parse_sig([sig])
            pubkey, address = parse_xpub(x_pubkey)
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            print_error("cannot find address in input script", bytes.encode('hex'))
            return
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, 2 of n
    match = [ opcodes.OP_0 ] + [ opcodes.OP_PUSHDATA4 ] * (len(decoded) - 1)

    if not match_decoded(decoded, match):
        print_error("cannot find address in input script", bytes.encode('hex'))
        return

    x_sig = [x[1].encode('hex') for x in decoded[1:-1]]
    d['signatures'] = parse_sig(x_sig)
    d['num_sig'] = 2

    dec2 = [ x for x in script_GetOp(decoded[-1][1]) ]
    match_2of2 = [ opcodes.OP_2, opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4, opcodes.OP_2, opcodes.OP_CHECKMULTISIG ]
    match_2of3 = [ opcodes.OP_2, opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4, opcodes.OP_3, opcodes.OP_CHECKMULTISIG ]
    if match_decoded(dec2, match_2of2):
        x_pubkeys = [ dec2[1][1].encode('hex'), dec2[2][1].encode('hex') ]
    elif match_decoded(dec2, match_2of3):
        x_pubkeys = [ dec2[1][1].encode('hex'), dec2[2][1].encode('hex'), dec2[3][1].encode('hex') ]
    else:
        print_error("cannot find address in input script", bytes.encode('hex'))
        return

    d['x_pubkeys'] = x_pubkeys
    pubkeys = [parse_xpub(x)[0] for x in x_pubkeys]     # xpub, addr = parse_xpub()
    d['pubkeys'] = pubkeys
    redeemScript = Transaction.multisig_script(pubkeys,2)
    d['redeemScript'] = redeemScript
    d['address'] = hash_160_to_bc_address(hash_160(redeemScript.decode('hex')), 5)




def get_address_from_output_script(bytes):
    decoded = [ x for x in script_GetOp(bytes) ]

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]
    if match_decoded(decoded, match):
        return 'pubkey', decoded[0][1].encode('hex')

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [ opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]
    if match_decoded(decoded, match):
        return 'address', hash_160_to_bc_address(decoded[2][1])

    # p2sh
    match = [ opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL ]
    if match_decoded(decoded, match):
        return 'address', hash_160_to_bc_address(decoded[1][1],5)

    # OP_RETURN
    match = [ opcodes.OP_RETURN, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        return 'op_return', decoded[1][1]

    return "(None)", "(None)"





def parse_input(vds):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    d['scriptSig'] = scriptSig = vds.read_bytes(vds.read_compact_size())
    sequence = vds.read_uint32()
    if prevout_hash == '00'*32:
        d['is_coinbase'] = True
    else:
        d['is_coinbase'] = False
        d['prevout_hash'] = prevout_hash
        d['prevout_n'] = prevout_n
        d['sequence'] = sequence
        d['pubkeys'] = []
        d['signatures'] = {}
        d['address'] = None
        if scriptSig:
            parse_scriptSig(d, scriptSig)
    return d


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = scriptPubKey.encode('hex')
    d['prevout_n'] = i
    return d


def deserialize(raw):
    vds = BCDataStream()
    vds.write(raw.decode('hex'))
    d = {}
    start = vds.read_cursor
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    d['inputs'] = list(parse_input(vds) for i in xrange(n_vin))
    n_vout = vds.read_compact_size()
    d['outputs'] = list(parse_output(vds,i) for i in xrange(n_vout))
    d['lockTime'] = vds.read_uint32()
    return d


def push_script(x):
    return op_push(len(x)/2) + x


class Transaction:

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, inputs, outputs, locktime=0):
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
        self.raw = None

    @classmethod
    def deserialize(klass, raw):
        self = klass([],[])
        self.update(raw)
        return self

    def update(self, raw):
        d = deserialize(raw)
        self.raw = raw
        self.inputs = d['inputs']
        self.outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        self.locktime = d['lockTime']

    @classmethod
    def sweep(klass, privkeys, network, to_address, fee):
        inputs = []
        for privkey in privkeys:
            pubkey = public_key_from_private_key(privkey)
            address = address_from_private_key(privkey)
            u = network.synchronous_get([ ('blockchain.address.listunspent',[address])])[0]
            pay_script = klass.pay_script('address', address)
            for item in u:
                item['scriptPubKey'] = pay_script
                item['redeemPubkey'] = pubkey
                item['address'] = address
                item['prevout_hash'] = item['tx_hash']
                item['prevout_n'] = item['tx_pos']
                item['pubkeys'] = [pubkey]
                item['x_pubkeys'] = [None]
                item['signatures'] = [None]
                item['num_sig'] = 1
            inputs += u

        if not inputs:
            return

        total = sum(i.get('value') for i in inputs) - fee
        outputs = [('address', to_address, total)]
        self = klass(inputs, outputs)
        self.sign({ pubkey:privkey })
        return self

    @classmethod
    def multisig_script(klass, public_keys, num=None):
        n = len(public_keys)
        if num is None: num = n

        assert num <= n and n in [2,3] , 'Only "2 of 2", and "2 of 3" transactions are supported'

        if num==2:
            s = '52'
        elif num == 3:
            s = '53'
        else:
            raise

        for k in public_keys:
            s += op_push(len(k)/2) + k
        if n==2:
            s += '52'
        elif n==3:
            s += '53'
        else:
            raise
        s += 'ae'

        return s


    @classmethod
    def pay_script(self, type, addr):
        if type == 'op_return':
            h = addr.encode('hex')
            return '6a' + push_script(h)
        else:
            assert type == 'address'
        addrtype, hash_160 = bc_address_to_hash_160(addr)
        if addrtype == 30:
            script = '76a9'                                      # op_dup, op_hash_160
            script += push_script(hash_160.encode('hex'))
            script += '88ac'                                     # op_equalverify, op_checksig
        elif addrtype == 22:
            script = 'a9'                                        # op_hash_160
            script += push_script(hash_160.encode('hex'))
            script += '87'                                       # op_equal
        else:
            raise
        return script


    def serialize(self, for_sig=None):
        # for_sig:
        #   -1   : do not sign, estimate length
        #   i>=0 : serialized tx for signing input i
        #   None : add all known signatures

        inputs = self.inputs
        outputs = self.outputs

        s  = int_to_hex(1,4)                                         # version
        s += var_int( len(inputs) )                                  # number of inputs
        for i, txin in enumerate(inputs):

            s += txin['prevout_hash'].decode('hex')[::-1].encode('hex')   # prev hash
            s += int_to_hex(txin['prevout_n'],4)                          # prev index

            p2sh = txin.get('redeemScript') is not None
            num_sig = txin['num_sig']
            address = txin['address']

            x_signatures = txin['signatures']
            signatures = filter(None, x_signatures)
            is_complete = len(signatures) == num_sig

            if for_sig in [-1, None]:
                # if we have enough signatures, we use the actual pubkeys
                # use extended pubkeys (with bip32 derivation)
                if for_sig == -1:
                    # we assume that signature will be 0x48 bytes long
                    pubkeys = txin['pubkeys']
                    sig_list = [ "00" * 0x48 ] * num_sig
                elif is_complete:
                    pubkeys = txin['pubkeys']
                    sig_list = ((sig + '01') for sig in signatures)
                else:
                    pubkeys = txin['x_pubkeys']
                    sig_list = ((sig + '01') if sig else NO_SIGNATURE for sig in x_signatures)
                script = ''.join(push_script(x) for x in sig_list)
                if not p2sh:
                    x_pubkey = pubkeys[0]
                    if x_pubkey is None:
                        addrtype, h160 = bc_address_to_hash_160(txin['address'])
                        x_pubkey = 'fd' + (chr(addrtype) + h160).encode('hex')
                    script += push_script(x_pubkey)
                else:
                    script = '00' + script          # put op_0 in front of script
                    redeem_script = self.multisig_script(pubkeys,2)
                    script += push_script(redeem_script)

            elif for_sig==i:
                script = txin['redeemScript'] if p2sh else self.pay_script('address', address)
            else:
                script = ''

            s += var_int( len(script)/2 )                            # script length
            s += script
            s += "ffffffff"                                          # sequence

        s += var_int( len(outputs) )                                 # number of outputs
        for output in outputs:
            type, addr, amount = output
            s += int_to_hex( amount, 8)                              # amount
            script = self.pay_script(type, addr)
            s += var_int( len(script)/2 )                           #  script length
            s += script                                             #  script
        s += int_to_hex(0,4)                                        #  lock time
        if for_sig is not None and for_sig != -1:
            s += int_to_hex(1, 4)                                   #  hash type
        return s

    def tx_for_sig(self,i):
        return self.serialize(for_sig = i)

    def hash(self):
        return Hash(self.raw.decode('hex') )[::-1].encode('hex')

    def add_input(self, input):
        self.inputs.append(input)
        self.raw = None

    def input_value(self):
        return sum(x['value'] for x in self.inputs)

    def output_value(self):
        return sum( val for tp,addr,val in self.outputs)

    def get_fee(self):
        return self.input_value() - self.output_value()

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs:
            if txin.get('is_coinbase'):
                continue
            signatures = filter(None, txin['signatures'])
            s += len(signatures)
            r += txin['num_sig']
        return s, r

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    def inputs_to_sign(self):
        out = set()
        for txin in self.inputs:
            x_signatures = txin['signatures']
            signatures = filter(None, x_signatures)
            if len(signatures) == txin['num_sig']:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                out.add(x_pubkey)
        return out

    def sign(self, keypairs):
        print_error("tx.sign(), keypairs:", keypairs)
        for i, txin in enumerate(self.inputs):
            signatures = filter(None, txin['signatures'])
            num = txin['num_sig']
            if len(signatures) == num:
                # continue if this txin is complete
                continue

            for x_pubkey in txin['x_pubkeys']:
                if x_pubkey in keypairs.keys():
                    print_error("adding signature for", x_pubkey)
                    # add pubkey to txin
                    txin = self.inputs[i]
                    x_pubkeys = txin['x_pubkeys']
                    ii = x_pubkeys.index(x_pubkey)
                    sec = keypairs[x_pubkey]
                    pubkey = public_key_from_private_key(sec)
                    txin['x_pubkeys'][ii] = pubkey
                    txin['pubkeys'][ii] = pubkey
                    self.inputs[i] = txin
                    # add signature
                    for_sig = Hash(self.tx_for_sig(i).decode('hex'))
                    pkey = regenerate_key(sec)
                    secexp = pkey.secret
                    private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
                    public_key = private_key.get_verifying_key()
                    sig = private_key.sign_digest_deterministic( for_sig, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der )
                    assert public_key.verify_digest( sig, for_sig, sigdecode = ecdsa.util.sigdecode_der)
                    txin['signatures'][ii] = sig.encode('hex')
                    self.inputs[i] = txin

        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()


    def add_pubkey_addresses(self, txdict):
        for txin in self.inputs:
            if txin.get('address') == "(pubkey)":
                prev_tx = txdict.get(txin.get('prevout_hash'))
                if prev_tx:
                    address, value = prev_tx.get_outputs()[txin.get('prevout_n')]
                    print_error("found pay-to-pubkey address:", address)
                    txin["address"] = address


    def get_outputs(self):
        """convert pubkeys to addresses"""
        o = []
        for type, x, v in self.outputs:
            if type == 'address':
                addr = x
            elif type == 'pubkey':
                addr = public_key_to_bc_address(x.decode('hex'))
            elif type == 'op_return':
                try:
                    addr = 'OP_RETURN: "' + x.decode('utf8') + '"'
                except:
                    addr = 'OP_RETURN: "' + x.encode('hex') + '"'
            else:
                addr = "(None)"
            o.append((addr,v))      # consider using yield (addr, v)
        return o

    def get_output_addresses(self):
        return [addr for addr, val in self.get_outputs()]


    def has_address(self, addr):
        return (addr in self.get_output_addresses()) or (addr in (tx.get("address") for tx in self.inputs))


    def get_value(self, addresses, prevout_values):
        # return the balance for that tx
        is_relevant = False
        is_send = False
        is_pruned = False
        is_partial = False
        v_in = v_out = v_out_mine = 0

        for item in self.inputs:
            addr = item.get('address')
            if addr in addresses:
                is_send = True
                is_relevant = True
                key = item['prevout_hash']  + ':%d'%item['prevout_n']
                value = prevout_values.get( key )
                if value is None:
                    is_pruned = True
                else:
                    v_in += value
            else:
                is_partial = True

        if not is_send: is_partial = False

        for addr, value in self.get_outputs():
            v_out += value
            if addr in addresses:
                v_out_mine += value
                is_relevant = True

        if is_pruned:
            # some inputs are mine:
            fee = None
            if is_send:
                v = v_out_mine - v_out
            else:
                # no input is mine
                v = v_out_mine

        else:
            v = v_out_mine - v_in

            if is_partial:
                # some inputs are mine, but not all
                fee = None
                is_send = v < 0
            else:
                # all inputs are mine
                fee = v_out - v_in

        return is_relevant, is_send, v, fee


    def as_dict(self):
        import json
        out = {
            "hex":str(self),
            "complete":self.is_complete()
            }
        return out


    def requires_fee(self, verifier):
        # see https://en.bitcoin.it/wiki/Transaction_fees
        #
        # size must be smaller than 1 kbyte for free tx
        size = len(self.serialize(-1))/2
        if size >= 10000:
            return True
        # all outputs must be 0.01 BTC or larger for free tx
        for addr, value in self.get_outputs():
            if value < 1000000:
                return True
        # priority must be large enough for free tx
        threshold = 57600000
        weight = 0
        for txin in self.inputs:
            age = verifier.get_confirmations(txin["prevout_hash"])[0]
            weight += txin["value"] * age
        priority = weight / size
        print_error(priority, threshold)

        return priority < threshold
