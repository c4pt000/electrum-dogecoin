# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'electrum_nmc/electrum/gui/qt/forms/dnssubdomaindialog.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_DNSSubDomainDialog(object):
    def setupUi(self, DNSSubDomainDialog):
        DNSSubDomainDialog.setObjectName("DNSSubDomainDialog")
        DNSSubDomainDialog.resize(400, 100)
        self.verticalLayout = QtWidgets.QVBoxLayout(DNSSubDomainDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.labelSubDomain = QtWidgets.QLabel(DNSSubDomainDialog)
        self.labelSubDomain.setObjectName("labelSubDomain")
        self.verticalLayout.addWidget(self.labelSubDomain)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.editSubDomain = QtWidgets.QLineEdit(DNSSubDomainDialog)
        self.editSubDomain.setObjectName("editSubDomain")
        self.horizontalLayout.addWidget(self.editSubDomain)
        self.label_2 = QtWidgets.QLabel(DNSSubDomainDialog)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout.addWidget(self.label_2)
        self.labelDomainName = QtWidgets.QLabel(DNSSubDomainDialog)
        self.labelDomainName.setObjectName("labelDomainName")
        self.horizontalLayout.addWidget(self.labelDomainName)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.btnAdd = QtWidgets.QDialogButtonBox(DNSSubDomainDialog)
        self.btnAdd.setOrientation(QtCore.Qt.Horizontal)
        self.btnAdd.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.btnAdd.setObjectName("btnAdd")
        self.verticalLayout.addWidget(self.btnAdd)

        self.retranslateUi(DNSSubDomainDialog)
        self.btnAdd.accepted.connect(DNSSubDomainDialog.accept)
        self.btnAdd.rejected.connect(DNSSubDomainDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(DNSSubDomainDialog)

    def retranslateUi(self, DNSSubDomainDialog):
        _translate = QtCore.QCoreApplication.translate
        DNSSubDomainDialog.setWindowTitle(_translate("DNSSubDomainDialog", "Dialog"))
        self.labelSubDomain.setText(_translate("DNSSubDomainDialog", "Select a subdomain to add to your domain."))
        self.editSubDomain.setPlaceholderText(_translate("DNSSubDomainDialog", "e.g., www"))
        self.label_2.setText(_translate("DNSSubDomainDialog", "."))
        self.labelDomainName.setText(_translate("DNSSubDomainDialog", "domain.bit"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    DNSSubDomainDialog = QtWidgets.QDialog()
    ui = Ui_DNSSubDomainDialog()
    ui.setupUi(DNSSubDomainDialog)
    DNSSubDomainDialog.show()
    sys.exit(app.exec_())

