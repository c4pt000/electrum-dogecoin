from PyQt4.QtGui import *
from electrum_doge.plugins import BasePlugin, hook
from electrum_doge.i18n import _

class Plugin(BasePlugin):


    def fullname(self):
        return 'Virtual Keyboard'

    def description(self):
        return '%s\n%s' % (_("Add an optional virtual keyboard to the password dialog."), _("Warning: do not use this if it makes you pick a weaker password."))

    @hook
    def init_qt(self, gui):
        self.gui = gui
        self.vkb = None
        self.vkb_index = 0

    @hook
    def password_dialog(self, pw, grid, pos):
        vkb_button = QPushButton(_("+"))
        vkb_button.setFixedWidth(20)
        vkb_button.clicked.connect(lambda: self.toggle_vkb(grid, pw))
        grid.addWidget(vkb_button, pos, 2)
        self.kb_pos = 2


    def toggle_vkb(self, grid, pw):
        if self.vkb: grid.removeItem(self.vkb)
        self.vkb = self.virtual_keyboard(self.vkb_index, pw)
        grid.addLayout(self.vkb, self.kb_pos, 0, 1, 3)
        self.vkb_index += 1


    def virtual_keyboard(self, i, pw):
        import random
        i = i%3
        if i == 0:
            chars = 'abcdefghijklmnopqrstuvwxyz '
        elif i == 1:
            chars = 'ABCDEFGHIJKLMNOPQRTSUVWXYZ '
        elif i == 2:
            chars = '1234567890!?.,;:/%&()[]{}+-'
            
        n = len(chars)
        s = []
        for i in xrange(n):
            while True:
                k = random.randint(0,n-1)
                if k not in s:
                    s.append(k)
                    break

        def add_target(t):
            return lambda: pw.setText(str( pw.text() ) + t)
            
        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.setSpacing(2)
        for i in range(n):
            l_button = QPushButton(chars[s[i]])
            l_button.setFixedWidth(25)
            l_button.setFixedHeight(25)
            l_button.clicked.connect(add_target(chars[s[i]]) )
            grid.addWidget(l_button, i/6, i%6)

        vbox.addLayout(grid)

        return vbox

