import os, sys, re, json
import platform
import shutil
from datetime import datetime
from i18n import _

class NotEnoughFunds(Exception): pass

class InvalidPassword(Exception):
    def __str__(self):
        return _("Incorrect password")

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        from transaction import Transaction
        if isinstance(obj, Transaction):
            return obj.as_dict()
        return super(MyEncoder, self).default(obj)

# integer division in Python returns the floor of the result instead of truncating towards zero like C
def cdiv(x, y):
    return int(float(x) / float(y))

is_verbose = False
def set_verbosity(b):
    global is_verbose
    is_verbose = b


def print_error(*args):
    if not is_verbose: return
    print_stderr(*args)

def print_stderr(*args):
    args = [str(item) for item in args]
    sys.stderr.write(" ".join(args) + "\n")
    sys.stderr.flush()

def print_msg(*args):
    # Stringify args
    args = [str(item) for item in args]
    sys.stdout.write(" ".join(args) + "\n")
    sys.stdout.flush()

def print_json(obj):
    try:
        s = json.dumps(obj, sort_keys = True, indent = 4, cls=MyEncoder)
    except TypeError:
        s = repr(obj)
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def user_dir():
    if "HOME" in os.environ:
        return os.path.join(os.environ["HOME"], ".electrum-doge")
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], "Electrum-DOGE")
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], "Electrum-DOGE")
    elif 'ANDROID_DATA' in os.environ:
        return "/sdcard/electrum-doge/"
    else:
        #raise Exception("No home directory found in environment variables.")
        return


def data_dir():
    import __builtin__
    if __builtin__.use_local_modules:
        return local_data_dir()
    else:
        return appdata_dir()

def usr_share_dir():
    return os.path.join(sys.prefix, "share")

def appdata_dir():
    """Find the path to the application data directory; add an electrum-doge folder and return path."""
    if platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "Electrum-DOGE")
    elif platform.system() == "Linux":
        return os.path.join(sys.prefix, "share", "electrum-doge")
    elif (platform.system() == "Darwin" or
          platform.system() == "DragonFly" or
          platform.system() == "OpenBSD" or
          platform.system() == "FreeBSD" or
	  platform.system() == "NetBSD"):
        return "/Library/Application Support/Electrum-DOGE"
    else:
        raise Exception("Unknown system")


def get_resource_path(*args):
    return os.path.join(".", *args)


def local_data_dir():
    """Return path to the data folder."""
    assert sys.argv
    prefix_path = os.path.dirname(sys.argv[0])
    local_data = os.path.join(prefix_path, "data")
    return local_data


def format_satoshis(x, is_diff=False, num_zeros = 0, decimal_point = 8, whitespaces=False):
    from decimal import Decimal
    s = Decimal(x)
    sign, digits, exp = s.as_tuple()
    digits = map(str, digits)
    while len(digits) < decimal_point + 1:
        digits.insert(0,'0')
    digits.insert(-decimal_point,'.')
    s = ''.join(digits).rstrip('0')
    if sign:
        s = '-' + s
    elif is_diff:
        s = "+" + s

    p = s.find('.')
    s += "0"*( 1 + num_zeros - ( len(s) - p ))
    if whitespaces:
        s += " "*( 1 + decimal_point - ( len(s) - p ))
        s = " "*( 13 - decimal_point - ( p )) + s
    return s


# Takes a timestamp and returns a string with the approximation of the age
def age(from_date, since_date = None, target_tz=None, include_seconds=False):
    if from_date is None:
        return "Unknown"

    from_date = datetime.fromtimestamp(from_date)
    if since_date is None:
        since_date = datetime.now(target_tz)

    distance_in_time = since_date - from_date
    distance_in_seconds = int(round(abs(distance_in_time.days * 86400 + distance_in_time.seconds)))
    distance_in_minutes = int(round(distance_in_seconds/60))

    if distance_in_minutes <= 1:
        if include_seconds:
            for remainder in [5, 10, 20]:
                if distance_in_seconds < remainder:
                    return "less than %s seconds ago" % remainder
            if distance_in_seconds < 40:
                return "half a minute ago"
            elif distance_in_seconds < 60:
                return "less than a minute ago"
            else:
                return "1 minute ago"
        else:
            if distance_in_minutes == 0:
                return "less than a minute ago"
            else:
                return "1 minute ago"
    elif distance_in_minutes < 45:
        return "%s minutes ago" % distance_in_minutes
    elif distance_in_minutes < 90:
        return "about 1 hour ago"
    elif distance_in_minutes < 1440:
        return "about %d hours ago" % (round(distance_in_minutes / 60.0))
    elif distance_in_minutes < 2880:
        return "1 day ago"
    elif distance_in_minutes < 43220:
        return "%d days ago" % (round(distance_in_minutes / 1440))
    elif distance_in_minutes < 86400:
        return "about 1 month ago"
    elif distance_in_minutes < 525600:
        return "%d months ago" % (round(distance_in_minutes / 43200))
    elif distance_in_minutes < 1051200:
        return "about 1 year ago"
    else:
        return "over %d years ago" % (round(distance_in_minutes / 525600))


# URL decode
#_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
#urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)

def parse_URI(uri):
    import urlparse
    import bitcoin
    from decimal import Decimal

    if ':' not in uri:
        assert bitcoin.is_address(uri)
        return uri, None, None, None, None

    u = urlparse.urlparse(uri)
    assert u.scheme == 'dogecoin'

    address = u.path
    valid_address = bitcoin.is_address(address)

    pq = urlparse.parse_qs(u.query)

    for k, v in pq.items():
        if len(v)!=1:
            raise Exception('Duplicate Key', k)

    amount = label = message = request_url = ''
    if 'amount' in pq:
        am = pq['amount'][0]
        m = re.match('([0-9\.]+)X([0-9])', am)
        if m:
            k = int(m.group(2)) - 8
            amount = Decimal(m.group(1)) * pow(  Decimal(10) , k)
        else:
            amount = Decimal(am) * 100000000
    if 'message' in pq:
        message = pq['message'][0]
    if 'label' in pq:
        label = pq['label'][0]
    if 'r' in pq:
        request_url = pq['r'][0]

    if request_url != '':
        return address, amount, label, message, request_url

    assert valid_address

    return address, amount, label, message, request_url


# Python bug (http://bugs.python.org/issue1927) causes raw_input
# to be redirected improperly between stdin/stderr on Unix systems
def raw_input(prompt=None):
    if prompt:
        sys.stdout.write(prompt)
    return builtin_raw_input()
import __builtin__
builtin_raw_input = __builtin__.raw_input
__builtin__.raw_input = raw_input



def parse_json(message):
    n = message.find('\n')
    if n==-1:
        return None, message
    try:
        j = json.loads( message[0:n] )
    except:
        j = None
    return j, message[n+1:]




class timeout(Exception):
    pass

import socket
import errno
import json
import ssl
import traceback
import time

class SocketPipe:

    def __init__(self, socket):
        self.socket = socket
        self.message = ''
        self.set_timeout(0.1)

    def set_timeout(self, t):
        self.socket.settimeout(t)

    def get(self):
        while True:
            response, self.message = parse_json(self.message)
            if response:
                return response
            try:
                data = self.socket.recv(1024)
            except socket.timeout:
                raise timeout
            except ssl.SSLError:
                raise timeout
            except socket.error, err:
                if err.errno == 60:
                    raise timeout
                elif err.errno in [11, 10035]:
                    print_error("socket errno", err.errno)
                    time.sleep(0.1)
                    continue
                else:
                    print_error("pipe: socket error", err)
                    data = ''
            except:
                traceback.print_exc(file=sys.stderr)
                data = ''

            if not data:
                self.socket.close()
                return None
            self.message += data

    def send(self, request):
        out = json.dumps(request) + '\n'
        self._send(out)

    def send_all(self, requests):
        out = ''.join(map(lambda x: json.dumps(x) + '\n', requests))
        self._send(out)

    def _send(self, out):
        while out:
            try:
                sent = self.socket.send(out)
                out = out[sent:]
            except ssl.SSLError as e:
                print_error("SSLError:", e)
                time.sleep(0.1)
                continue
            except socket.error as e:
                if e[0] in (errno.EWOULDBLOCK,errno.EAGAIN):
                    print_error("EAGAIN: retrying")
                    time.sleep(0.1)
                    continue
                elif e[0] in ['timed out', 'The write operation timed out']:
                    print_error("socket timeout, retry")
                    time.sleep(0.1)
                    continue
                else:
                    traceback.print_exc(file=sys.stdout)
                    raise e



import Queue

class QueuePipe:

    def __init__(self, send_queue=None, get_queue=None):
        self.send_queue = send_queue if send_queue else Queue.Queue()
        self.get_queue = get_queue if get_queue else Queue.Queue()
        self.set_timeout(0.1)

    def get(self):
        try:
            return self.get_queue.get(timeout=self.timeout)
        except Queue.Empty:
            raise timeout

    def get_all(self):
        responses = []
        while True:
            try:
                r = self.get_queue.get_nowait()
                responses.append(r)
            except Queue.Empty:
                break
        return responses

    def set_timeout(self, t):
        self.timeout = t

    def send(self, request):
        self.send_queue.put(request)

    def send_all(self, requests):
        for request in requests:
            self.send(request)
