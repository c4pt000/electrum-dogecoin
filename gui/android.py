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




from __future__ import absolute_import
import android

from electrum_doge import SimpleConfig, Wallet, WalletStorage, format_satoshis, mnemonic_encode, mnemonic_decode
from electrum_doge.bitcoin import is_valid
from electrum_doge import util
from decimal import Decimal
import datetime, re



def modal_dialog(title, msg = None):
    droid.dialogCreateAlert(title,msg)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogShow()
    droid.dialogGetResponse()
    droid.dialogDismiss()

def modal_input(title, msg, value = None, etype=None):
    droid.dialogCreateInput(title, msg, value, etype)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse()
    result = response.result
    droid.dialogDismiss()

    if result is None:
        print "modal input: result is none"
        return modal_input(title, msg, value, etype)

    if result.get('which') == 'positive':
        return result.get('value')

def modal_question(q, msg, pos_text = 'OK', neg_text = 'Cancel'):
    droid.dialogCreateAlert(q, msg)
    droid.dialogSetPositiveButtonText(pos_text)
    droid.dialogSetNegativeButtonText(neg_text)
    droid.dialogShow()
    response = droid.dialogGetResponse()
    result = response.result
    droid.dialogDismiss()

    if result is None:
        print "modal question: result is none"
        return modal_question(q,msg, pos_text, neg_text)

    return result.get('which') == 'positive'

def edit_label(addr):
    v = modal_input('Edit label',None,wallet.labels.get(addr))
    if v is not None:
        if v:
            wallet.labels[addr] = v
        else:
            if addr in wallet.labels.keys():
                wallet.labels.pop(addr)
        wallet.update_tx_history()
        wallet.save()
        droid.fullSetProperty("labelTextView", "text", v)

def select_from_contacts():
    title = 'Contacts:'
    droid.dialogCreateAlert(title)
    l = []
    for i in range(len(wallet.addressbook)):
        addr = wallet.addressbook[i]
        label = wallet.labels.get(addr,addr)
        l.append( label )
    droid.dialogSetItems(l)
    droid.dialogSetPositiveButtonText('New contact')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    droid.dialogDismiss()

    if response.get('which') == 'positive':
        return 'newcontact'

    result = response.get('item')
    print result
    if result is not None:
        addr = wallet.addressbook[result]
        return addr


def select_from_addresses():
    droid.dialogCreateAlert("Addresses:")
    l = []
    addresses = wallet.addresses()
    for i in range(len(addresses)):
        addr = addresses[i]
        label = wallet.labels.get(addr,addr)
        l.append( label )
    droid.dialogSetItems(l)
    droid.dialogShow()
    response = droid.dialogGetResponse()
    result = response.result.get('item')
    droid.dialogDismiss()
    if result is not None:
        addr = addresses[result]
        return addr


def protocol_name(p):
    if p == 't': return 'TCP'
    if p == 'h': return 'HTTP'
    if p == 's': return 'SSL'
    if p == 'g': return 'HTTPS'


def protocol_dialog(host, protocol, z):
    droid.dialogCreateAlert('Protocol',host)
    if z:
        protocols = z.keys()
    else:
        protocols = 'thsg'
    l = []
    current = protocols.index(protocol)
    for p in protocols:
        l.append(protocol_name(p))
    droid.dialogSetSingleChoiceItems(l, current)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    selected_item = droid.dialogGetSelectedItems().result
    droid.dialogDismiss()

    if not response: return
    if not selected_item: return
    if response.get('which') == 'positive':
        return protocols[selected_item[0]]




def make_layout(s, scrollable = False):
    content = """

      <LinearLayout 
        android:id="@+id/zz"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" 
        android:background="#ff222222">

        <TextView
          android:id="@+id/textElectrum"
          android:text="Electrum-DOGE"
          android:textSize="7pt"
          android:textColor="#ff4444ff"
          android:gravity="left"
          android:layout_height="wrap_content"
          android:layout_width="match_parent"
        />
      </LinearLayout>

        %s   """%s

    if scrollable:
        content = """
      <ScrollView 
        android:id="@+id/scrollview"
        android:layout_width="match_parent"
        android:layout_height="match_parent" >

      <LinearLayout
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="wrap_content" >

      %s

      </LinearLayout>
      </ScrollView>
      """%content


    return """<?xml version="1.0" encoding="utf-8"?>
      <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:id="@+id/background"
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="match_parent" 
        android:background="#ff000022">

      %s 
      </LinearLayout>"""%content




def main_layout():
    return make_layout("""
        <TextView android:id="@+id/balanceTextView" 
                android:layout_width="match_parent"
                android:text=""
                android:textColor="#ffffffff"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:padding="7dip"
                android:textSize="8pt"
                android:gravity="center_vertical|center_horizontal|left">
        </TextView>

        <TextView android:id="@+id/historyTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Recent transactions"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
        </TextView>

        %s """%get_history_layout(15),True)



def qr_layout(addr):
    return make_layout("""

     <TextView android:id="@+id/addrTextView" 
                android:layout_width="match_parent"
                android:layout_height="50" 
                android:text="%s"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
     </TextView>

     <ImageView
        android:id="@+id/qrView"
        android:gravity="center"
        android:layout_width="match_parent"
        android:layout_height="350"
        android:antialias="false"
        android:src="file:///sdcard/sl4a/qrcode.bmp" /> 

     <TextView android:id="@+id/labelTextView" 
                android:layout_width="match_parent"
                android:layout_height="50" 
                android:text="%s"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
     </TextView>

     """%(addr,wallet.labels.get(addr,'')), True)

payto_layout = make_layout("""

        <TextView android:id="@+id/recipientTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Pay to:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>


        <EditText android:id="@+id/recipient"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" android:inputType="text">
        </EditText>

        <LinearLayout android:id="@+id/linearLayout1"
                android:layout_width="match_parent"
                android:layout_height="wrap_content">
                <Button android:id="@+id/buttonQR" android:layout_width="wrap_content"
                        android:layout_height="wrap_content" android:text="From QR code"></Button>
                <Button android:id="@+id/buttonContacts" android:layout_width="wrap_content"
                        android:layout_height="wrap_content" android:text="From Contacts"></Button>
        </LinearLayout>


        <TextView android:id="@+id/labelTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Description:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>

        <EditText android:id="@+id/label"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" android:inputType="text">
        </EditText>

        <TextView android:id="@+id/amountLabelTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Amount:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>

        <EditText android:id="@+id/amount"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" android:inputType="numberDecimal">
        </EditText>

        <LinearLayout android:layout_width="match_parent"
                android:layout_height="wrap_content" android:id="@+id/linearLayout1">
                <Button android:id="@+id/buttonPay" android:layout_width="wrap_content"
                        android:layout_height="wrap_content" android:text="Send"></Button>
        </LinearLayout>""",False)



settings_layout = make_layout(""" <ListView
           android:id="@+id/myListView" 
           android:layout_width="match_parent"
           android:layout_height="wrap_content" />""")



def get_history_values(n):
    values = []
    h = wallet.get_tx_history()
    length = min(n, len(h))
    for i in range(length):
        tx_hash, conf, is_mine, value, fee, balance, timestamp = h[-i-1]
        try:
            dt = datetime.datetime.fromtimestamp( timestamp )
            if dt.date() == dt.today().date():
                time_str = str( dt.time() )
            else:
                time_str = str( dt.date() )
        except Exception:
            time_str = 'pending'

        conf_str = 'v' if conf else 'o'
        label, is_default_label = wallet.get_label(tx_hash)
        values.append((conf_str, '  ' + time_str, '  ' + format_satoshis(value,True), '  ' + label ))

    return values


def get_history_layout(n):
    rows = ""
    i = 0
    values = get_history_values(n)
    for v in values:
        a,b,c,d = v
        color = "#ff00ff00" if a == 'v' else "#ffff0000"
        rows += """
        <TableRow>
          <TextView
            android:id="@+id/hl_%d_col1" 
            android:layout_column="0"
            android:text="%s"
            android:textColor="%s"
            android:padding="3" />
          <TextView
            android:id="@+id/hl_%d_col2" 
            android:layout_column="1"
            android:text="%s"
            android:padding="3" />
          <TextView
            android:id="@+id/hl_%d_col3" 
            android:layout_column="2"
            android:text="%s"
            android:padding="3" />
          <TextView
            android:id="@+id/hl_%d_col4" 
            android:layout_column="3"
            android:text="%s"
            android:padding="4" />
        </TableRow>"""%(i,a,color,i,b,i,c,i,d)
        i += 1

    output = """
<TableLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="fill_parent"
    android:layout_height="wrap_content"
    android:stretchColumns="0,1,2,3">
    %s
</TableLayout>"""% rows
    return output


def set_history_layout(n):
    values = get_history_values(n)
    i = 0
    for v in values:
        a,b,c,d = v
        droid.fullSetProperty("hl_%d_col1"%i,"text", a)

        if a == 'v':
            droid.fullSetProperty("hl_%d_col1"%i, "textColor","#ff00ff00")
        else:
            droid.fullSetProperty("hl_%d_col1"%i, "textColor","#ffff0000")

        droid.fullSetProperty("hl_%d_col2"%i,"text", b)
        droid.fullSetProperty("hl_%d_col3"%i,"text", c)
        droid.fullSetProperty("hl_%d_col4"%i,"text", d)
        i += 1




status_text = ''
def update_layout():
    global status_text
    if not network.is_connected():
        text = "Not connected..."
    elif not wallet.up_to_date:
        text = "Synchronizing..."
    else:
        c, u = wallet.get_balance()
        text = "Balance:"+format_satoshis(c) 
        if u : text += '   [' + format_satoshis(u,True).strip() + ']'


    # vibrate if status changed
    if text != status_text:
        if status_text and network.is_connected() and wallet.up_to_date:
            droid.vibrate()
        status_text = text

    droid.fullSetProperty("balanceTextView", "text", status_text)

    if wallet.up_to_date:
        set_history_layout(15)




def pay_to(recipient, amount, fee, label):

    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Password').result
        if not password: return
    else:
        password = None

    droid.dialogCreateSpinnerProgress("Electrum-DOGE", "signing transaction...")
    droid.dialogShow()

    try:
        tx = wallet.mktx( [(recipient, amount)], password, fee)
    except Exception as e:
        modal_dialog('error', e.message)
        droid.dialogDismiss()
        return

    if label: 
        wallet.labels[tx.hash()] = label

    droid.dialogDismiss()

    r, h = wallet.sendtx( tx )
    if r:
        modal_dialog('Payment sent', h)
        return True
    else:
        modal_dialog('Error', h)







def make_new_contact():
    code = droid.scanBarcode()
    r = code.result
    if r:
        data = r['extras']['SCAN_RESULT']
        if data:
            if re.match('^dogecoin:', data):
                address, _, _, _, _ = util.parse_URI(data)
            elif is_valid(data):
                address = data
            else:
                address = None
            if address:
                if modal_question('Add to contacts?', address):
                    wallet.add_contact(address)
        else:
            modal_dialog('Invalid address', data)


do_refresh = False

def update_callback():
    global do_refresh
    print "gui callback", network.is_connected()
    do_refresh = True
    droid.eventPost("refresh",'z')

def main_loop():
    global do_refresh

    update_layout()
    out = None
    quitting = False
    while out is None:

        event = droid.eventWait(1000).result
        if event is None:
            if do_refresh: 
                update_layout()
                do_refresh = False
            continue

        print "got event in main loop", repr(event)
        if event == 'OK': continue
        if event is None: continue
        if not event.get("name"): continue

        # request 2 taps before we exit
        if event["name"]=="key":
            if event["data"]["key"] == '4':
                if quitting:
                    out = 'quit'
                else: 
                    quitting = True
        else: quitting = False

        if event["name"]=="click":
            id=event["data"]["id"]

        elif event["name"]=="settings":
            out = 'settings'

        elif event["name"] in menu_commands:
            out = event["name"]

            if out == 'contacts':
                global contact_addr
                contact_addr = select_from_contacts()
                if contact_addr == 'newcontact':
                    make_new_contact()
                    contact_addr = None
                if not contact_addr:
                    out = None

            elif out == "receive":
                global receive_addr
                receive_addr = select_from_addresses()
                if receive_addr:
                    amount = modal_input('Amount', 'Amount you want receive. ', '', "numberDecimal")
                    if amount:
                        receive_addr = 'dogecoin:%s?amount=%s'%(receive_addr, amount)

                if not receive_addr:
                    out = None


    return out
                    

def payto_loop():
    global recipient
    if recipient:
        droid.fullSetProperty("recipient","text",recipient)
        recipient = None

    out = None
    while out is None:
        event = droid.eventWait().result
        if not event: continue
        print "got event in payto loop", event
        if event == 'OK': continue
        if not event.get("name"): continue

        if event["name"] == "click":
            id = event["data"]["id"]

            if id=="buttonPay":

                droid.fullQuery()
                recipient = droid.fullQueryDetail("recipient").result.get('text')
                label  = droid.fullQueryDetail("label").result.get('text')
                amount = droid.fullQueryDetail('amount').result.get('text')

                if not is_valid(recipient):
                    modal_dialog('Error','Invalid Dogecoin address')
                    continue

                try:
                    amount = int( 100000000 * Decimal(amount) )
                except Exception:
                    modal_dialog('Error','Invalid amount')
                    continue

                result = pay_to(recipient, amount, wallet.fee, label)
                if result:
                    out = 'main'

            elif id=="buttonContacts":
                addr = select_from_contacts()
                droid.fullSetProperty("recipient","text",addr)

            elif id=="buttonQR":
                code = droid.scanBarcode()
                r = code.result
                if r:
                    data = r['extras']['SCAN_RESULT']
                    if data:
                        if re.match('^bitcoin:', data):
                            payto, amount, label, _, _ = util.parse_URI(data)
                            droid.fullSetProperty("recipient", "text",payto)
                            droid.fullSetProperty("amount", "text", amount)
                            droid.fullSetProperty("label", "text", label)
                        else:
                            droid.fullSetProperty("recipient", "text", data)

                    
        elif event["name"] in menu_commands:
            out = event["name"]

        elif event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'main'

        #elif event["name"]=="screen":
        #    if event["data"]=="destroy":
        #        out = 'main'

    return out


receive_addr = ''
contact_addr = ''
recipient = ''

def receive_loop():
    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event
        if event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'main'

        elif event["name"]=="clipboard":
            droid.setClipboard(receive_addr)
            modal_dialog('Address copied to clipboard',receive_addr)

        elif event["name"]=="edit":
            edit_label(receive_addr)

    return out

def contacts_loop():
    global recipient
    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event
        if event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'main'

        elif event["name"]=="clipboard":
            droid.setClipboard(contact_addr)
            modal_dialog('Address copied to clipboard',contact_addr)

        elif event["name"]=="edit":
            edit_label(contact_addr)

        elif event["name"]=="paytocontact":
            recipient = contact_addr
            out = 'send'

        elif event["name"]=="deletecontact":
            if modal_question('delete contact', contact_addr):
                out = 'main'

    return out


def server_dialog(servers):
    droid.dialogCreateAlert("Public servers")
    droid.dialogSetItems( servers.keys() )
    droid.dialogSetPositiveButtonText('Private server')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    droid.dialogDismiss()
    if not response: return

    if response.get('which') == 'positive':
        return modal_input('Private server', None)

    i = response.get('item')
    if i is not None:
        response = servers.keys()[i]
        return response


def show_seed():
    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Seed').result
        if not password: return
    else:
        password = None
    
    try:
        seed = wallet.get_seed(password)
    except Exception:
        modal_dialog('error','incorrect password')
        return

    modal_dialog('Your seed is',seed)
    modal_dialog('Mnemonic code:', ' '.join(mnemonic_encode(seed)) )

def change_password_dialog():
    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Your wallet is encrypted').result
        if password is None: return
    else:
        password = None

    try:
        wallet.get_seed(password)
    except Exception:
        modal_dialog('error','incorrect password')
        return

    new_password  = droid.dialogGetPassword('Choose a password').result
    if new_password == None:
        return

    if new_password != '':
        password2  = droid.dialogGetPassword('Confirm new password').result
        if new_password != password2:
            modal_dialog('error','passwords do not match')
            return

    wallet.update_password(password, new_password)
    if new_password:
        modal_dialog('Password updated','your wallet is encrypted')
    else:
        modal_dialog('No password','your wallet is not encrypted')
    return True


def settings_loop():


    def set_listview():
        host, port, p = network.default_server.split(':')
        fee = str( Decimal( wallet.fee)/100000000 )
        is_encrypted = 'yes' if wallet.use_encryption else 'no'
        protocol = protocol_name(p)
        droid.fullShow(settings_layout)
        droid.fullSetList("myListView",['Server: ' + host, 'Protocol: '+ protocol, 'Port: '+port, 'Transaction fee: '+fee, 'Password: '+is_encrypted, 'Seed'])

    set_listview()

    out = None
    while out is None:
        event = droid.eventWait()
        event = event.result
        print "got event", event
        if event == 'OK': continue
        if not event: continue

        servers = network.get_servers()
        name = event.get("name")
        if not name: continue

        if name == "itemclick":
            pos = event["data"]["position"]
            host, port, protocol = network.default_server.split(':')
            network_changed = False

            if pos == "0": #server
                host = server_dialog(servers)
                if host:
                    p = servers[host]
                    port = p[protocol]
                    network_changed = True

            elif pos == "1": #protocol
                if host in servers:
                    protocol = protocol_dialog(host, protocol, servers[host])
                    z = servers[host]
                    port = z[protocol]
                    network_changed = True

            elif pos == "2": #port
                a_port = modal_input('Port number', 'If you use a public server, this field is set automatically when you set the protocol', port, "number")
                if a_port != port:
                    port = a_port
                    network_changed = True

            elif pos == "3": #fee
                fee = modal_input('Transaction fee', 'The fee will be this amount multiplied by the number of inputs in your transaction. ', str( Decimal( wallet.fee)/100000000 ), "numberDecimal")
                if fee:
                    try:
                        fee = int( 100000000 * Decimal(fee) )
                    except Exception:
                        modal_dialog('error','invalid fee value')
                    wallet.set_fee(fee)
                    set_listview()

            elif pos == "4":
                if change_password_dialog():
                    set_listview()

            elif pos == "5":
                show_seed()

            if network_changed:
                proxy = None
                auto_connect = False
                try:
                    network.set_parameters(host, port, protocol, proxy, auto_connect)
                except Exception:
                    modal_dialog('error','invalid server')
                set_listview()

        elif name in menu_commands:
            out = event["name"]

        elif name == 'cancel':
            out = 'main'

        elif name == "key":
            if event["data"]["key"] == '4':
                out = 'main'

    return out

def add_menu(s):
    droid.clearOptionsMenu()
    if s == 'main':
        droid.addOptionsMenuItem("Send","send",None,"")
        droid.addOptionsMenuItem("Receive","receive",None,"")
        droid.addOptionsMenuItem("Contacts","contacts",None,"")
        droid.addOptionsMenuItem("Settings","settings",None,"")
    elif s == 'receive':
        droid.addOptionsMenuItem("Copy","clipboard",None,"")
        droid.addOptionsMenuItem("Label","edit",None,"")
    elif s == 'contacts':
        droid.addOptionsMenuItem("Copy","clipboard",None,"")
        droid.addOptionsMenuItem("Label","edit",None,"")
        droid.addOptionsMenuItem("Pay to","paytocontact",None,"")
        #droid.addOptionsMenuItem("Delete","deletecontact",None,"")


def make_bitmap(addr):
    # fixme: this is highly inefficient
    droid.dialogCreateSpinnerProgress("please wait")
    droid.dialogShow()
    try:
        import pyqrnative, bmp
        qr = pyqrnative.QRCode(4, pyqrnative.QRErrorCorrectLevel.L)
        qr.addData(addr)
        qr.make()
        k = qr.getModuleCount()
        assert k == 33
        bmp.save_qrcode(qr,"/sdcard/sl4a/qrcode.bmp")
    finally:
        droid.dialogDismiss()

        


droid = android.Android()
menu_commands = ["send", "receive", "settings", "contacts", "main"]
wallet = None
network = None

class ElectrumGui:

    def __init__(self, config, _network):
        global wallet, network
        network = _network
        network.register_callback('updated', update_callback)
        network.register_callback('connected', update_callback)
        network.register_callback('disconnected', update_callback)
        network.register_callback('disconnecting', update_callback)
        
        storage = WalletStorage(config)
        if not storage.file_exists:
            action = self.restore_or_create()
            if not action: exit()

            wallet = Wallet(storage)
            if action == 'create':
                wallet.init_seed(None)
                self.show_seed()
                wallet.save_seed(None)
                wallet.synchronize()  # generate first addresses offline
                
            elif action == 'restore':
                seed = self.seed_dialog()
                if not seed:
                    exit()
                wallet.init_seed(str(seed))
                wallet.save_seed(None)
            else:
                exit()

            wallet.start_threads(network)

            if action == 'restore':
                if not self.restore_wallet():
                    exit()

            self.password_dialog()

        else:
            wallet = Wallet(storage)
            wallet.start_threads(network)


    def main(self, url):
        s = 'main'
        while True:
            add_menu(s)
            if s == 'main':
                droid.fullShow(main_layout())
                s = main_loop()

            elif s == 'send':
                droid.fullShow(payto_layout)
                s = payto_loop()

            elif s == 'receive':
                make_bitmap(receive_addr)
                droid.fullShow(qr_layout(receive_addr))
                s = receive_loop()

            elif s == 'contacts':
                make_bitmap(contact_addr)
                droid.fullShow(qr_layout(contact_addr))
                s = contacts_loop()

            elif s == 'settings':
                s = settings_loop()

            else:
                break

        droid.makeToast("Bye!")


    def restore_or_create(self):
        droid.dialogCreateAlert("Wallet not found","Do you want to create a new wallet, or restore an existing one?")
        droid.dialogSetPositiveButtonText('Create')
        droid.dialogSetNeutralButtonText('Restore')
        droid.dialogSetNegativeButtonText('Cancel')
        droid.dialogShow()
        response = droid.dialogGetResponse().result
        droid.dialogDismiss()
        if not response: return
        if response.get('which') == 'negative':
            return

        return 'restore' if response.get('which') == 'neutral' else 'create'


    def seed_dialog(self):
        if modal_question("Enter your seed","Input method",'QR Code', 'mnemonic'):
            code = droid.scanBarcode()
            r = code.result
            if r:
                seed = r['extras']['SCAN_RESULT']
            else:
                return
        else:
            m = modal_input('Mnemonic','please enter your code')
            try:
                seed = mnemonic_decode(m.split(' '))
            except Exception:
                modal_dialog('error: could not decode this seed')
                return

        return str(seed)


    def network_dialog(self):
        return True

        
    def show_seed(self):
        modal_dialog('Your seed is:', wallet.seed)
        modal_dialog('Mnemonic code:', ' '.join(mnemonic_encode(wallet.seed)) )


    def password_dialog(self):
        change_password_dialog()


    def restore_wallet(self):

        msg = "recovering wallet..."
        droid.dialogCreateSpinnerProgress("Electrum-DOGE", msg)
        droid.dialogShow()

        wallet.restore(lambda x: None)

        droid.dialogDismiss()
        droid.vibrate()

        if wallet.is_found():
            wallet.fill_addressbook()
            modal_dialog("recovery successful")
        else:
            if not modal_question("no transactions found for this seed","do you want to keep this wallet?"):
                return False

        return True

