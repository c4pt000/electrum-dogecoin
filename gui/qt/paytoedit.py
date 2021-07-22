#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from qrtextedit import ScanQRTextEdit

import re
from decimal import Decimal
from electrum_doge import bitcoin

RE_ADDRESS = '[1-9A-HJ-NP-Za-km-z]{26,}'
RE_ALIAS = '(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>'

frozen_style = "QWidget { background-color:none; border:none;}"
normal_style = "QPlainTextEdit { }"

class PayToEdit(ScanQRTextEdit):
    def __init__(self, win):
        super(PayToEdit,self).__init__(win=win)
        self.amount_edit = win.amount_e
        self.document().contentsChanged.connect(self.update_size)
        self.heightMin = 0
        self.heightMax = 150
        self.c = None
        self.textChanged.connect(self.check_text)
        self.outputs = []
        self.errors = []
        self.is_pr = False
        self.scan_f = self.win.pay_from_URI
        self.update_size()
        self.payto_address = None

    def lock_amount(self):
        self.amount_edit.setFrozen(True)

    def unlock_amount(self):
        self.amount_edit.setFrozen(False)

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setStyleSheet(frozen_style if b else normal_style)
        self.button.setHidden(b)

    def setGreen(self):
        self.is_pr = True
        self.setStyleSheet("QWidget { background-color:#80ff80;}")

    def setExpired(self):
        self.is_pr = True
        self.setStyleSheet("QWidget { background-color:#ffcccc;}")

    def parse_address_and_amount(self, line):
        m = re.match('^OP_RETURN\s+"(.+)"$', line.strip())
        if m:
            type = 'op_return'
            address = m.group(1)
            amount = 0
        else:
            x, y = line.split(',')
            type = 'address'
            address = self.parse_address(x)
            amount = self.parse_amount(y)
        return type, address, amount


    def parse_amount(self, x):
        p = pow(10, self.amount_edit.decimal_point())
        return int( p * Decimal(x.strip()))


    def parse_address(self, line):
        r = line.strip()
        m = re.match('^'+RE_ALIAS+'$', r)
        address = m.group(2) if m else r
        assert bitcoin.is_address(address)
        return address


    def check_text(self):
        self.errors = []
        if self.is_pr:
            return

        # filter out empty lines
        lines = filter( lambda x: x, self.lines())
        outputs = []
        total = 0

        self.payto_address = None

        if len(lines) == 1:
            try:
                self.payto_address = self.parse_address(lines[0])
            except:
                pass

            if self.payto_address:
                self.unlock_amount()
                return

        for i, line in enumerate(lines):
            try:
                type, to_address, amount = self.parse_address_and_amount(line)
            except:
                self.errors.append((i, line.strip()))
                continue

            outputs.append((type, to_address, amount))
            total += amount

        self.outputs = outputs
        self.payto_address = None

        if outputs:
            self.amount_edit.setAmount(total)
        else:
            self.amount_edit.setText("")

        self.amount_edit.textEdited.emit("")

        if total or len(lines)>1:
            self.lock_amount()
        else:
            self.unlock_amount()


    def get_errors(self):
        return self.errors

    def get_outputs(self):
        if self.payto_address:
            try:
                amount = self.amount_edit.get_amount()
            except:
                amount = None
            self.outputs = [('address', self.payto_address, amount)]

        return self.outputs[:]


    def lines(self):
        return str(self.toPlainText()).split('\n')


    def is_multiline(self):
        return len(self.lines()) > 1


    def update_size(self):
        docHeight = self.document().size().height()
        h = docHeight*17 + 11
        if self.heightMin <= h <= self.heightMax:
            self.setMinimumHeight(h)
            self.setMaximumHeight(h)
        self.verticalScrollBar().hide()


    def setCompleter(self, completer):
        self.c = completer
        self.c.setWidget(self)
        self.c.setCompletionMode(QCompleter.PopupCompletion)
        self.c.activated.connect(self.insertCompletion)


    def insertCompletion(self, completion):
        if self.c.widget() != self:
            return
        tc = self.textCursor()
        extra = completion.length() - self.c.completionPrefix().length()
        tc.movePosition(QTextCursor.Left)
        tc.movePosition(QTextCursor.EndOfWord)
        tc.insertText(completion.right(extra))
        self.setTextCursor(tc)


    def textUnderCursor(self):
        tc = self.textCursor()
        tc.select(QTextCursor.WordUnderCursor)
        return tc.selectedText()


    def keyPressEvent(self, e):
        if self.isReadOnly():
            return

        if self.c.popup().isVisible():
            if e.key() in [Qt.Key_Enter, Qt.Key_Return]:
                e.ignore()
                return

        if e.key() in [Qt.Key_Tab]:
            e.ignore()
            return

        if e.key() in [Qt.Key_Down, Qt.Key_Up] and not self.is_multiline():
            e.ignore()
            return

        QPlainTextEdit.keyPressEvent(self, e)

        ctrlOrShift = e.modifiers() and (Qt.ControlModifier or Qt.ShiftModifier)
        if self.c is None or (ctrlOrShift and e.text().isEmpty()):
            return

        eow = QString("~!@#$%^&*()_+{}|:\"<>?,./;'[]\\-=")
        hasModifier = (e.modifiers() != Qt.NoModifier) and not ctrlOrShift;
        completionPrefix = self.textUnderCursor()

        if hasModifier or e.text().isEmpty() or completionPrefix.length() < 1 or eow.contains(e.text().right(1)):
            self.c.popup().hide()
            return

        if completionPrefix != self.c.completionPrefix():
            self.c.setCompletionPrefix(completionPrefix);
            self.c.popup().setCurrentIndex(self.c.completionModel().index(0, 0))

        cr = self.cursorRect()
        cr.setWidth(self.c.popup().sizeHintForColumn(0) + self.c.popup().verticalScrollBar().sizeHint().width())
        self.c.complete(cr)


    def qr_input(self):
        data = super(PayToEdit,self).qr_input()
        if data.startswith("dogecoin:"):
            self.scan_f(data)
            # TODO: update fee
