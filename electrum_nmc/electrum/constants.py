# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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

import os
import json

from .util import inv_dict
from . import bitcoin


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


GIT_REPO_URL = "https://github.com/namecoin/electrum-nmc"
GIT_REPO_ISSUES_URL = "https://github.com/namecoin/electrum-nmc/issues"


class AbstractNet:

    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 0

    @classmethod
    def max_checkpoint(cls) -> int:
        # Namecoin: We can't actually fully use the last checkpoint, because
        # verifying the chunk following the last checkpoint requires having the
        # chunk for the last checkpoint, because of the timewarp hardfork.  So
        # we artificially return one fewer checkpoint than is available.
        #
        # It should be noted that this hack causes Electrum-NMC to need at
        # least 2 checkpoints, whereas upstream Electrum only needs 1.
        #return max(0, len(cls.CHECKPOINTS) * 2016 - 1)
        return max(0, (len(cls.CHECKPOINTS)-1) * 2016 - 1)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(bitcoin.rev_hex(cls.GENESIS))


class BitcoinMainnet(AbstractNet):

    TESTNET = False
    WIF_PREFIX = 158
    ADDRTYPE_P2PKH = 30
    ADDRTYPE_P2SH = 22
#    SEGWIT_HRP = "doge"
    GENESIS = "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"
    DEFAULT_PORTS = {'t': '50011', 's': '50022'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = read_json('', [])
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 497000

    XPRV_HEADERS = {
        'standard':    0x02fac398,  # 0x0488ade4,  # xprv
#        'p2wpkh-p2sh': 0x049d7878,  # yprv
#        'p2wsh-p2sh':  0x0295b005,  # Yprv
#        'p2wpkh':      0x04b2430c,  # zprv
#        'p2wsh':       0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x02facafd,   #xpub        orig# 0x0488b21e,  # xpub
#        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
#        'p2wsh-p2sh':  0x0295b43f,  # Ypub
#        'p2wpkh':      0x04b24746,  # zpub
#        'p2wsh':       0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 3
    LN_REALM_BYTE = 0
    LN_DNS_SEEDS = []

    AUXPOW_CHAIN_ID = 0x0062
    AUXPOW_START_HEIGHT = 19200

    NAME_EXPIRATION = 36000


class BitcoinTestnet(AbstractNet):

    TESTNET = True
    WIF_PREFIX = 239
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tn"
    GENESIS = "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = read_json('checkpoints_testnet.json', [])

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh':  0x024285b5,  # Uprv
        'p2wpkh':      0x045f18bc,  # vprv
        'p2wsh':       0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh':  0x024289ef,  # Upub
        'p2wpkh':      0x045f1cf6,  # vpub
        'p2wsh':       0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 1
    LN_REALM_BYTE = 1
    LN_DNS_SEEDS = []

    AUXPOW_CHAIN_ID = 0x0001
    AUXPOW_START_HEIGHT = 0

    NAME_EXPIRATION = 36000


class BitcoinRegtest(BitcoinTestnet):

    SEGWIT_HRP = "ncrt"
    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []
    LN_DNS_SEEDS = []

    NAME_EXPIRATION = 30


class BitcoinSimnet(BitcoinTestnet):

    WIF_PREFIX = 0x64
    ADDRTYPE_P2PKH = 0x3f
    ADDRTYPE_P2SH = 0x7b
    SEGWIT_HRP = "sb"
    GENESIS = "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []
    LN_DNS_SEEDS = []


# don't import net directly, import the module instead (so that net is singleton)
net = BitcoinMainnet

def set_simnet():
    global net
    net = BitcoinSimnet

def set_mainnet():
    global net
    net = BitcoinMainnet

def set_testnet():
    global net
    net = BitcoinTestnet


def set_regtest():
    global net
    net = BitcoinRegtest
