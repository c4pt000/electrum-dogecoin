# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'electrum_nmc/electrum/gui/qt/forms/dnsdialog.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_DNSDialog(object):
    def setupUi(self, DNSDialog):
        DNSDialog.setObjectName("DNSDialog")
        DNSDialog.resize(692, 635)
        DNSDialog.setModal(True)
        self.verticalLayout = QtWidgets.QVBoxLayout(DNSDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout_15 = QtWidgets.QVBoxLayout()
        self.verticalLayout_15.setObjectName("verticalLayout_15")
        self.labelDomain = QtWidgets.QLabel(DNSDialog)
        self.labelDomain.setObjectName("labelDomain")
        self.verticalLayout_15.addWidget(self.labelDomain)
        self.comboDomain = QtWidgets.QComboBox(DNSDialog)
        self.comboDomain.setObjectName("comboDomain")
        self.verticalLayout_15.addWidget(self.comboDomain)
        self.verticalLayout.addLayout(self.verticalLayout_15)
        self.labelCreateRecord = QtWidgets.QLabel(DNSDialog)
        self.labelCreateRecord.setTextFormat(QtCore.Qt.PlainText)
        self.labelCreateRecord.setObjectName("labelCreateRecord")
        self.verticalLayout.addWidget(self.labelCreateRecord)
        self.tabRecords = QtWidgets.QTabWidget(DNSDialog)
        self.tabRecords.setMaximumSize(QtCore.QSize(16777215, 269))
        self.tabRecords.setObjectName("tabRecords")
        self.tabA = QtWidgets.QWidget()
        self.tabA.setObjectName("tabA")
        self.verticalLayout_Main = QtWidgets.QVBoxLayout(self.tabA)
        self.verticalLayout_Main.setObjectName("verticalLayout_Main")
        self.labelADesc = QtWidgets.QLabel(self.tabA)
        self.labelADesc.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.labelADesc.setWordWrap(True)
        self.labelADesc.setObjectName("labelADesc")
        self.verticalLayout_Main.addWidget(self.labelADesc)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.labelHostType = QtWidgets.QLabel(self.tabA)
        self.labelHostType.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelHostType.setObjectName("labelHostType")
        self.verticalLayout_3.addWidget(self.labelHostType)
        self.comboHostType = QtWidgets.QComboBox(self.tabA)
        self.comboHostType.setObjectName("comboHostType")
        self.comboHostType.addItem("")
        self.comboHostType.addItem("")
        self.comboHostType.addItem("")
        self.comboHostType.addItem("")
        self.comboHostType.addItem("")
        self.comboHostType.addItem("")
        self.verticalLayout_3.addWidget(self.comboHostType)
        self.horizontalLayout_2.addLayout(self.verticalLayout_3)
        self.verticalLayout_8 = QtWidgets.QVBoxLayout()
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.labelAHostname = QtWidgets.QLabel(self.tabA)
        self.labelAHostname.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelAHostname.setObjectName("labelAHostname")
        self.verticalLayout_8.addWidget(self.labelAHostname)
        self.editAHostname = QValidatedLineEdit(self.tabA)
        self.editAHostname.setText("")
        self.editAHostname.setObjectName("editAHostname")
        self.verticalLayout_8.addWidget(self.editAHostname)
        self.horizontalLayout_2.addLayout(self.verticalLayout_8)
        self.verticalLayout_Main.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem)
        self.btnACreate = QtWidgets.QPushButton(self.tabA)
        self.btnACreate.setObjectName("btnACreate")
        self.horizontalLayout_3.addWidget(self.btnACreate)
        self.verticalLayout_Main.addLayout(self.horizontalLayout_3)
        self.tabRecords.addTab(self.tabA, "")
        self.tabCNAME = QtWidgets.QWidget()
        self.tabCNAME.setObjectName("tabCNAME")
        self.verticalLayout_Network = QtWidgets.QVBoxLayout(self.tabCNAME)
        self.verticalLayout_Network.setObjectName("verticalLayout_Network")
        self.labelCNAMEDesc = QtWidgets.QLabel(self.tabCNAME)
        self.labelCNAMEDesc.setWordWrap(True)
        self.labelCNAMEDesc.setObjectName("labelCNAMEDesc")
        self.verticalLayout_Network.addWidget(self.labelCNAMEDesc)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.verticalLayout_12 = QtWidgets.QVBoxLayout()
        self.verticalLayout_12.setObjectName("verticalLayout_12")
        self.labelCNAMEAlias = QtWidgets.QLabel(self.tabCNAME)
        self.labelCNAMEAlias.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelCNAMEAlias.setObjectName("labelCNAMEAlias")
        self.verticalLayout_12.addWidget(self.labelCNAMEAlias)
        self.editCNAMEAlias = QValidatedLineEdit(self.tabCNAME)
        self.editCNAMEAlias.setText("")
        self.editCNAMEAlias.setObjectName("editCNAMEAlias")
        self.verticalLayout_12.addWidget(self.editCNAMEAlias)
        self.horizontalLayout_6.addLayout(self.verticalLayout_12)
        self.verticalLayout_Network.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem1)
        self.btnCNAMECreate = QtWidgets.QPushButton(self.tabCNAME)
        self.btnCNAMECreate.setObjectName("btnCNAMECreate")
        self.horizontalLayout_7.addWidget(self.btnCNAMECreate)
        self.verticalLayout_Network.addLayout(self.horizontalLayout_7)
        self.tabRecords.addTab(self.tabCNAME, "")
        self.tabNS = QtWidgets.QWidget()
        self.tabNS.setAutoFillBackground(False)
        self.tabNS.setObjectName("tabNS")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.tabNS)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.labelNSDesc = QtWidgets.QLabel(self.tabNS)
        self.labelNSDesc.setWordWrap(True)
        self.labelNSDesc.setObjectName("labelNSDesc")
        self.verticalLayout_2.addWidget(self.labelNSDesc)
        self.editNSHosts = QValidatedLineEdit(self.tabNS)
        self.editNSHosts.setObjectName("editNSHosts")
        self.verticalLayout_2.addWidget(self.editNSHosts)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem2)
        self.btnNSCreate = QtWidgets.QPushButton(self.tabNS)
        self.btnNSCreate.setObjectName("btnNSCreate")
        self.horizontalLayout_5.addWidget(self.btnNSCreate)
        self.verticalLayout_2.addLayout(self.horizontalLayout_5)
        self.tabRecords.addTab(self.tabNS, "")
        self.tabDS = QtWidgets.QWidget()
        self.tabDS.setObjectName("tabDS")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.tabDS)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.labelDSDesc = QtWidgets.QLabel(self.tabDS)
        self.labelDSDesc.setWordWrap(True)
        self.labelDSDesc.setObjectName("labelDSDesc")
        self.verticalLayout_5.addWidget(self.labelDSDesc)
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.labelDSKeyTag = QtWidgets.QLabel(self.tabDS)
        self.labelDSKeyTag.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelDSKeyTag.setObjectName("labelDSKeyTag")
        self.verticalLayout_6.addWidget(self.labelDSKeyTag)
        self.editDSKeyTag = QValidatedLineEdit(self.tabDS)
        self.editDSKeyTag.setObjectName("editDSKeyTag")
        self.verticalLayout_6.addWidget(self.editDSKeyTag)
        self.horizontalLayout_8.addLayout(self.verticalLayout_6)
        self.verticalLayout_7 = QtWidgets.QVBoxLayout()
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.labelDSAlgorithm = QtWidgets.QLabel(self.tabDS)
        self.labelDSAlgorithm.setMaximumSize(QtCore.QSize(75, 20))
        self.labelDSAlgorithm.setObjectName("labelDSAlgorithm")
        self.verticalLayout_7.addWidget(self.labelDSAlgorithm)
        self.editDSAlgorithm = QValidatedLineEdit(self.tabDS)
        self.editDSAlgorithm.setMaximumSize(QtCore.QSize(75, 16777215))
        self.editDSAlgorithm.setObjectName("editDSAlgorithm")
        self.verticalLayout_7.addWidget(self.editDSAlgorithm)
        self.horizontalLayout_8.addLayout(self.verticalLayout_7)
        self.verticalLayout_10 = QtWidgets.QVBoxLayout()
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.labelDSHashType = QtWidgets.QLabel(self.tabDS)
        self.labelDSHashType.setMaximumSize(QtCore.QSize(75, 20))
        self.labelDSHashType.setObjectName("labelDSHashType")
        self.verticalLayout_10.addWidget(self.labelDSHashType)
        self.editDSHashType = QValidatedLineEdit(self.tabDS)
        self.editDSHashType.setMaximumSize(QtCore.QSize(75, 16777215))
        self.editDSHashType.setObjectName("editDSHashType")
        self.verticalLayout_10.addWidget(self.editDSHashType)
        self.horizontalLayout_8.addLayout(self.verticalLayout_10)
        self.verticalLayout_14 = QtWidgets.QVBoxLayout()
        self.verticalLayout_14.setObjectName("verticalLayout_14")
        self.labelDSHash = QtWidgets.QLabel(self.tabDS)
        self.labelDSHash.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelDSHash.setObjectName("labelDSHash")
        self.verticalLayout_14.addWidget(self.labelDSHash)
        self.editDSHash = QValidatedLineEdit(self.tabDS)
        self.editDSHash.setObjectName("editDSHash")
        self.verticalLayout_14.addWidget(self.editDSHash)
        self.horizontalLayout_8.addLayout(self.verticalLayout_14)
        self.verticalLayout_5.addLayout(self.horizontalLayout_8)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_9.addItem(spacerItem3)
        self.btnDSCreate = QtWidgets.QPushButton(self.tabDS)
        self.btnDSCreate.setObjectName("btnDSCreate")
        self.horizontalLayout_9.addWidget(self.btnDSCreate)
        self.verticalLayout_5.addLayout(self.horizontalLayout_9)
        self.tabRecords.addTab(self.tabDS, "")
        self.tabTLS = QtWidgets.QWidget()
        self.tabTLS.setObjectName("tabTLS")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.tabTLS)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.labelTLSDesc = QtWidgets.QLabel(self.tabTLS)
        self.labelTLSDesc.setWordWrap(True)
        self.labelTLSDesc.setObjectName("labelTLSDesc")
        self.verticalLayout_9.addWidget(self.labelTLSDesc)
        self.horizontalLayout_15 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_15.setObjectName("horizontalLayout_15")
        self.verticalLayout_25 = QtWidgets.QVBoxLayout()
        self.verticalLayout_25.setObjectName("verticalLayout_25")
        self.labelTLSProto = QtWidgets.QLabel(self.tabTLS)
        self.labelTLSProto.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelTLSProto.setObjectName("labelTLSProto")
        self.verticalLayout_25.addWidget(self.labelTLSProto)
        self.editTLSProto = QtWidgets.QLineEdit(self.tabTLS)
        self.editTLSProto.setObjectName("editTLSProto")
        self.verticalLayout_25.addWidget(self.editTLSProto)
        self.horizontalLayout_15.addLayout(self.verticalLayout_25)
        self.verticalLayout_18 = QtWidgets.QVBoxLayout()
        self.verticalLayout_18.setObjectName("verticalLayout_18")
        self.labelTLSPort = QtWidgets.QLabel(self.tabTLS)
        self.labelTLSPort.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelTLSPort.setObjectName("labelTLSPort")
        self.verticalLayout_18.addWidget(self.labelTLSPort)
        self.editTLSPort = QtWidgets.QLineEdit(self.tabTLS)
        self.editTLSPort.setObjectName("editTLSPort")
        self.verticalLayout_18.addWidget(self.editTLSPort)
        self.horizontalLayout_15.addLayout(self.verticalLayout_18)
        self.verticalLayout_13 = QtWidgets.QVBoxLayout()
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.labelTLSCertUsage = QtWidgets.QLabel(self.tabTLS)
        self.labelTLSCertUsage.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelTLSCertUsage.setObjectName("labelTLSCertUsage")
        self.verticalLayout_13.addWidget(self.labelTLSCertUsage)
        self.editTLSCertUsage = QValidatedLineEdit(self.tabTLS)
        self.editTLSCertUsage.setObjectName("editTLSCertUsage")
        self.verticalLayout_13.addWidget(self.editTLSCertUsage)
        self.horizontalLayout_15.addLayout(self.verticalLayout_13)
        self.verticalLayout_16 = QtWidgets.QVBoxLayout()
        self.verticalLayout_16.setObjectName("verticalLayout_16")
        self.labelTLSSelector = QtWidgets.QLabel(self.tabTLS)
        self.labelTLSSelector.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelTLSSelector.setObjectName("labelTLSSelector")
        self.verticalLayout_16.addWidget(self.labelTLSSelector)
        self.editTLSSelector = QValidatedLineEdit(self.tabTLS)
        self.editTLSSelector.setObjectName("editTLSSelector")
        self.verticalLayout_16.addWidget(self.editTLSSelector)
        self.horizontalLayout_15.addLayout(self.verticalLayout_16)
        self.verticalLayout_17 = QtWidgets.QVBoxLayout()
        self.verticalLayout_17.setObjectName("verticalLayout_17")
        self.labelTLSMatchingType = QtWidgets.QLabel(self.tabTLS)
        self.labelTLSMatchingType.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelTLSMatchingType.setObjectName("labelTLSMatchingType")
        self.verticalLayout_17.addWidget(self.labelTLSMatchingType)
        self.editTLSMatchingType = QValidatedLineEdit(self.tabTLS)
        self.editTLSMatchingType.setObjectName("editTLSMatchingType")
        self.verticalLayout_17.addWidget(self.editTLSMatchingType)
        self.horizontalLayout_15.addLayout(self.verticalLayout_17)
        self.verticalLayout_9.addLayout(self.horizontalLayout_15)
        self.label_24 = QtWidgets.QLabel(self.tabTLS)
        self.label_24.setObjectName("label_24")
        self.verticalLayout_9.addWidget(self.label_24)
        self.editTLSData = QtWidgets.QPlainTextEdit(self.tabTLS)
        self.editTLSData.setObjectName("editTLSData")
        self.verticalLayout_9.addWidget(self.editTLSData)
        self.horizontalLayout_16 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_16.setObjectName("horizontalLayout_16")
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_16.addItem(spacerItem4)
        self.btnTLSCreate = QtWidgets.QPushButton(self.tabTLS)
        self.btnTLSCreate.setObjectName("btnTLSCreate")
        self.horizontalLayout_16.addWidget(self.btnTLSCreate)
        self.verticalLayout_9.addLayout(self.horizontalLayout_16)
        self.tabRecords.addTab(self.tabTLS, "")
        self.tabSRV = QtWidgets.QWidget()
        self.tabSRV.setObjectName("tabSRV")
        self.verticalLayout_20 = QtWidgets.QVBoxLayout(self.tabSRV)
        self.verticalLayout_20.setObjectName("verticalLayout_20")
        self.labelSRVDesc = QtWidgets.QLabel(self.tabSRV)
        self.labelSRVDesc.setWordWrap(True)
        self.labelSRVDesc.setObjectName("labelSRVDesc")
        self.verticalLayout_20.addWidget(self.labelSRVDesc)
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.verticalLayout_21 = QtWidgets.QVBoxLayout()
        self.verticalLayout_21.setObjectName("verticalLayout_21")
        self.labelSRVPriority = QtWidgets.QLabel(self.tabSRV)
        self.labelSRVPriority.setMaximumSize(QtCore.QSize(55, 20))
        self.labelSRVPriority.setObjectName("labelSRVPriority")
        self.verticalLayout_21.addWidget(self.labelSRVPriority)
        self.editSRVPriority = QValidatedLineEdit(self.tabSRV)
        self.editSRVPriority.setMaximumSize(QtCore.QSize(80, 16777215))
        self.editSRVPriority.setObjectName("editSRVPriority")
        self.verticalLayout_21.addWidget(self.editSRVPriority)
        self.horizontalLayout_11.addLayout(self.verticalLayout_21)
        self.verticalLayout_23 = QtWidgets.QVBoxLayout()
        self.verticalLayout_23.setObjectName("verticalLayout_23")
        self.labelSRVWeight = QtWidgets.QLabel(self.tabSRV)
        self.labelSRVWeight.setMaximumSize(QtCore.QSize(90, 20))
        self.labelSRVWeight.setObjectName("labelSRVWeight")
        self.verticalLayout_23.addWidget(self.labelSRVWeight)
        self.editSRVWeight = QValidatedLineEdit(self.tabSRV)
        self.editSRVWeight.setMaximumSize(QtCore.QSize(90, 16777215))
        self.editSRVWeight.setObjectName("editSRVWeight")
        self.verticalLayout_23.addWidget(self.editSRVWeight)
        self.horizontalLayout_11.addLayout(self.verticalLayout_23)
        self.verticalLayout_24 = QtWidgets.QVBoxLayout()
        self.verticalLayout_24.setObjectName("verticalLayout_24")
        self.labelSRVPort = QtWidgets.QLabel(self.tabSRV)
        self.labelSRVPort.setMaximumSize(QtCore.QSize(55, 20))
        self.labelSRVPort.setObjectName("labelSRVPort")
        self.verticalLayout_24.addWidget(self.labelSRVPort)
        self.editSRVPort = QValidatedLineEdit(self.tabSRV)
        self.editSRVPort.setMaximumSize(QtCore.QSize(75, 16777215))
        self.editSRVPort.setObjectName("editSRVPort")
        self.verticalLayout_24.addWidget(self.editSRVPort)
        self.horizontalLayout_11.addLayout(self.verticalLayout_24)
        self.verticalLayout_26 = QtWidgets.QVBoxLayout()
        self.verticalLayout_26.setObjectName("verticalLayout_26")
        self.labelSRVHost = QtWidgets.QLabel(self.tabSRV)
        self.labelSRVHost.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelSRVHost.setObjectName("labelSRVHost")
        self.verticalLayout_26.addWidget(self.labelSRVHost)
        self.editSRVHost = QValidatedLineEdit(self.tabSRV)
        self.editSRVHost.setObjectName("editSRVHost")
        self.verticalLayout_26.addWidget(self.editSRVHost)
        self.horizontalLayout_11.addLayout(self.verticalLayout_26)
        self.verticalLayout_20.addLayout(self.horizontalLayout_11)
        self.horizontalLayout_17 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_17.setObjectName("horizontalLayout_17")
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_17.addItem(spacerItem5)
        self.btnSRVCreate = QtWidgets.QPushButton(self.tabSRV)
        self.btnSRVCreate.setObjectName("btnSRVCreate")
        self.horizontalLayout_17.addWidget(self.btnSRVCreate)
        self.verticalLayout_20.addLayout(self.horizontalLayout_17)
        self.tabRecords.addTab(self.tabSRV, "")
        self.tabTXT = QtWidgets.QWidget()
        self.tabTXT.setObjectName("tabTXT")
        self.verticalLayout_22 = QtWidgets.QVBoxLayout(self.tabTXT)
        self.verticalLayout_22.setObjectName("verticalLayout_22")
        self.labelTXTDesc = QtWidgets.QLabel(self.tabTXT)
        self.labelTXTDesc.setWordWrap(True)
        self.labelTXTDesc.setObjectName("labelTXTDesc")
        self.verticalLayout_22.addWidget(self.labelTXTDesc)
        self.editTXTData = QtWidgets.QLineEdit(self.tabTXT)
        self.editTXTData.setObjectName("editTXTData")
        self.verticalLayout_22.addWidget(self.editTXTData)
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        spacerItem6 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem6)
        self.btnTXTCreate = QtWidgets.QPushButton(self.tabTXT)
        self.btnTXTCreate.setObjectName("btnTXTCreate")
        self.horizontalLayout_12.addWidget(self.btnTXTCreate)
        self.verticalLayout_22.addLayout(self.horizontalLayout_12)
        self.tabRecords.addTab(self.tabTXT, "")
        self.tabIMPORT = QtWidgets.QWidget()
        self.tabIMPORT.setObjectName("tabIMPORT")
        self.verticalLayout_27 = QtWidgets.QVBoxLayout(self.tabIMPORT)
        self.verticalLayout_27.setObjectName("verticalLayout_27")
        self.labelIMPORTDesc = QtWidgets.QLabel(self.tabIMPORT)
        self.labelIMPORTDesc.setWordWrap(True)
        self.labelIMPORTDesc.setObjectName("labelIMPORTDesc")
        self.verticalLayout_27.addWidget(self.labelIMPORTDesc)
        self.horizontalLayout_18 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_18.setObjectName("horizontalLayout_18")
        self.verticalLayout_28 = QtWidgets.QVBoxLayout()
        self.verticalLayout_28.setObjectName("verticalLayout_28")
        self.labelIMPORTName = QtWidgets.QLabel(self.tabIMPORT)
        self.labelIMPORTName.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelIMPORTName.setObjectName("labelIMPORTName")
        self.verticalLayout_28.addWidget(self.labelIMPORTName)
        self.editIMPORTName = QValidatedLineEdit(self.tabIMPORT)
        self.editIMPORTName.setObjectName("editIMPORTName")
        self.verticalLayout_28.addWidget(self.editIMPORTName)
        self.horizontalLayout_18.addLayout(self.verticalLayout_28)
        self.verticalLayout_29 = QtWidgets.QVBoxLayout()
        self.verticalLayout_29.setObjectName("verticalLayout_29")
        self.labelIMPORTSubdomain = QtWidgets.QLabel(self.tabIMPORT)
        self.labelIMPORTSubdomain.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelIMPORTSubdomain.setObjectName("labelIMPORTSubdomain")
        self.verticalLayout_29.addWidget(self.labelIMPORTSubdomain)
        self.editIMPORTSubdomain = QValidatedLineEdit(self.tabIMPORT)
        self.editIMPORTSubdomain.setObjectName("editIMPORTSubdomain")
        self.verticalLayout_29.addWidget(self.editIMPORTSubdomain)
        self.horizontalLayout_18.addLayout(self.verticalLayout_29)
        self.verticalLayout_27.addLayout(self.horizontalLayout_18)
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_13.addItem(spacerItem7)
        self.btnIMPORTCreate = QtWidgets.QPushButton(self.tabIMPORT)
        self.btnIMPORTCreate.setObjectName("btnIMPORTCreate")
        self.horizontalLayout_13.addWidget(self.btnIMPORTCreate)
        self.verticalLayout_27.addLayout(self.horizontalLayout_13)
        self.tabRecords.addTab(self.tabIMPORT, "")
        self.tabSSHFP = QtWidgets.QWidget()
        self.tabSSHFP.setObjectName("tabSSHFP")
        self.verticalLayout_30 = QtWidgets.QVBoxLayout(self.tabSSHFP)
        self.verticalLayout_30.setObjectName("verticalLayout_30")
        self.labelSSHFPDesc = QtWidgets.QLabel(self.tabSSHFP)
        self.labelSSHFPDesc.setObjectName("labelSSHFPDesc")
        self.verticalLayout_30.addWidget(self.labelSSHFPDesc)
        self.horizontalLayout_19 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_19.setObjectName("horizontalLayout_19")
        self.verticalLayout_31 = QtWidgets.QVBoxLayout()
        self.verticalLayout_31.setObjectName("verticalLayout_31")
        self.labelSSHFPAlgorithm = QtWidgets.QLabel(self.tabSSHFP)
        self.labelSSHFPAlgorithm.setMaximumSize(QtCore.QSize(80, 20))
        self.labelSSHFPAlgorithm.setObjectName("labelSSHFPAlgorithm")
        self.verticalLayout_31.addWidget(self.labelSSHFPAlgorithm)
        self.editSSHFPAlgorithm = QValidatedLineEdit(self.tabSSHFP)
        self.editSSHFPAlgorithm.setMaximumSize(QtCore.QSize(80, 16777215))
        self.editSSHFPAlgorithm.setObjectName("editSSHFPAlgorithm")
        self.verticalLayout_31.addWidget(self.editSSHFPAlgorithm)
        self.horizontalLayout_19.addLayout(self.verticalLayout_31)
        self.verticalLayout_33 = QtWidgets.QVBoxLayout()
        self.verticalLayout_33.setObjectName("verticalLayout_33")
        self.labelSSHFPFingerprintType = QtWidgets.QLabel(self.tabSSHFP)
        self.labelSSHFPFingerprintType.setMaximumSize(QtCore.QSize(120, 20))
        self.labelSSHFPFingerprintType.setObjectName("labelSSHFPFingerprintType")
        self.verticalLayout_33.addWidget(self.labelSSHFPFingerprintType)
        self.editSSHFPFingerprintType = QValidatedLineEdit(self.tabSSHFP)
        self.editSSHFPFingerprintType.setMaximumSize(QtCore.QSize(120, 16777215))
        self.editSSHFPFingerprintType.setObjectName("editSSHFPFingerprintType")
        self.verticalLayout_33.addWidget(self.editSSHFPFingerprintType)
        self.horizontalLayout_19.addLayout(self.verticalLayout_33)
        self.verticalLayout_34 = QtWidgets.QVBoxLayout()
        self.verticalLayout_34.setObjectName("verticalLayout_34")
        self.labelSSHFPFingerprint = QtWidgets.QLabel(self.tabSSHFP)
        self.labelSSHFPFingerprint.setMaximumSize(QtCore.QSize(16777215, 20))
        self.labelSSHFPFingerprint.setObjectName("labelSSHFPFingerprint")
        self.verticalLayout_34.addWidget(self.labelSSHFPFingerprint)
        self.editSSHFPFingerprint = QValidatedLineEdit(self.tabSSHFP)
        self.editSSHFPFingerprint.setObjectName("editSSHFPFingerprint")
        self.verticalLayout_34.addWidget(self.editSSHFPFingerprint)
        self.horizontalLayout_19.addLayout(self.verticalLayout_34)
        self.verticalLayout_30.addLayout(self.horizontalLayout_19)
        self.horizontalLayout_14 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_14.setObjectName("horizontalLayout_14")
        spacerItem8 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_14.addItem(spacerItem8)
        self.btnSSHFPCreate = QtWidgets.QPushButton(self.tabSSHFP)
        self.btnSSHFPCreate.setObjectName("btnSSHFPCreate")
        self.horizontalLayout_14.addWidget(self.btnSSHFPCreate)
        self.verticalLayout_30.addLayout(self.horizontalLayout_14)
        self.tabRecords.addTab(self.tabSSHFP, "")
        self.verticalLayout.addWidget(self.tabRecords)
        self.layoutDNSRecords = QtWidgets.QVBoxLayout()
        self.layoutDNSRecords.setObjectName("layoutDNSRecords")
        self.labelDNSRecords = QtWidgets.QLabel(DNSDialog)
        self.labelDNSRecords.setObjectName("labelDNSRecords")
        self.layoutDNSRecords.addWidget(self.labelDNSRecords)
        self.listDNSRecords = QtWidgets.QTableView(DNSDialog)
        self.listDNSRecords.setMinimumSize(QtCore.QSize(0, 150))
        self.listDNSRecords.setObjectName("listDNSRecords")
        self.layoutDNSRecords.addWidget(self.listDNSRecords)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.totalSize = QtWidgets.QLabel(DNSDialog)
        self.totalSize.setObjectName("totalSize")
        self.horizontalLayout_10.addWidget(self.totalSize)
        self.labelBytes = QtWidgets.QLabel(DNSDialog)
        self.labelBytes.setMinimumSize(QtCore.QSize(50, 0))
        self.labelBytes.setText("")
        self.labelBytes.setObjectName("labelBytes")
        self.horizontalLayout_10.addWidget(self.labelBytes)
        self.labelOfTotal = QtWidgets.QLabel(DNSDialog)
        self.labelOfTotal.setObjectName("labelOfTotal")
        self.horizontalLayout_10.addWidget(self.labelOfTotal)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_10.addItem(spacerItem9)
        self.btnDeleteRecord = QtWidgets.QPushButton(DNSDialog)
        self.btnDeleteRecord.setObjectName("btnDeleteRecord")
        self.horizontalLayout_10.addWidget(self.btnDeleteRecord)
        self.btnEditRecord = QtWidgets.QPushButton(DNSDialog)
        self.btnEditRecord.setObjectName("btnEditRecord")
        self.horizontalLayout_10.addWidget(self.btnEditRecord)
        self.layoutDNSRecords.addLayout(self.horizontalLayout_10)
        self.verticalLayout.addLayout(self.layoutDNSRecords)
        self.buttonBox = QtWidgets.QDialogButtonBox(DNSDialog)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(DNSDialog)
        self.tabRecords.setCurrentIndex(0)
        self.buttonBox.accepted.connect(DNSDialog.accept)
        self.buttonBox.rejected.connect(DNSDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(DNSDialog)

    def retranslateUi(self, DNSDialog):
        _translate = QtCore.QCoreApplication.translate
        DNSDialog.setWindowTitle(_translate("DNSDialog", "DNS Builder"))
        self.labelDomain.setText(_translate("DNSDialog", "Domain"))
        self.labelCreateRecord.setText(_translate("DNSDialog", "Create new record"))
        self.labelADesc.setText(_translate("DNSDialog", "Namecoin A records are for IPv4, IPv6, Tor, Freenet, I2P, and ZeroNet addresses only and specify where your domain should direct to."))
        self.labelHostType.setText(_translate("DNSDialog", "Type"))
        self.comboHostType.setItemText(0, _translate("DNSDialog", "IPv4"))
        self.comboHostType.setItemText(1, _translate("DNSDialog", "IPv6"))
        self.comboHostType.setItemText(2, _translate("DNSDialog", "Tor"))
        self.comboHostType.setItemText(3, _translate("DNSDialog", "Freenet"))
        self.comboHostType.setItemText(4, _translate("DNSDialog", "I2P"))
        self.comboHostType.setItemText(5, _translate("DNSDialog", "ZeroNet"))
        self.labelAHostname.setText(_translate("DNSDialog", "Address"))
        self.editAHostname.setPlaceholderText(_translate("DNSDialog", "e.g., 192.168.0.1, rw6nbpjrmcpdxszn3air4bt7t75rpz4cp3c2kbdu72ptua57tzvin4id.onion"))
        self.btnACreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabA), _translate("DNSDialog", "A"))
        self.labelCNAMEDesc.setText(_translate("DNSDialog", "CNAME records act as an alias by mapping a hostname to another hostname. Absolute domain names must end with a dot (.)."))
        self.labelCNAMEAlias.setText(_translate("DNSDialog", "Alias of"))
        self.editCNAMEAlias.setPlaceholderText(_translate("DNSDialog", "e.g., namecoin.bit."))
        self.btnCNAMECreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabCNAME), _translate("DNSDialog", "CNAME"))
        self.labelNSDesc.setText(_translate("DNSDialog", "Master nameserver of the configured domain. Note that this delegates all IP related responsibility of this domain and its sub-domains to the master server, effectively bypassing other settings (e.g. A records). Absolute domains must end in a dot (.). IP addresses are not allowed."))
        self.editNSHosts.setPlaceholderText(_translate("DNSDialog", "e.g., ns1.myserver.net."))
        self.btnNSCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabNS), _translate("DNSDialog", "NS"))
        self.labelDSDesc.setText(_translate("DNSDialog", "DNSSEC fingerprints for securing the domain when used with DNS via NS. Format roughly mirrors RFC3658. "))
        self.labelDSKeyTag.setText(_translate("DNSDialog", "Keytag"))
        self.editDSKeyTag.setPlaceholderText(_translate("DNSDialog", "e.g., 31381"))
        self.labelDSAlgorithm.setText(_translate("DNSDialog", "Algorithm"))
        self.editDSAlgorithm.setPlaceholderText(_translate("DNSDialog", "e.g., 8"))
        self.labelDSHashType.setText(_translate("DNSDialog", "HashType"))
        self.editDSHashType.setPlaceholderText(_translate("DNSDialog", "e.g., 1"))
        self.labelDSHash.setText(_translate("DNSDialog", "Hash (Base64)"))
        self.editDSHash.setPlaceholderText(_translate("DNSDialog", "e.g., pA1W...ceTI="))
        self.btnDSCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabDS), _translate("DNSDialog", "DS"))
        self.labelTLSDesc.setText(_translate("DNSDialog", "A TLS record authenticates TLS servers without a public certificate authority.  For compatibility with ncp11 (e.g. Tor Browser), leave all settings other than Certificate Association Data at their default."))
        self.labelTLSProto.setText(_translate("DNSDialog", "Proto"))
        self.editTLSProto.setPlaceholderText(_translate("DNSDialog", "e.g., tcp"))
        self.editTLSProto.setText(_translate("DNSDialog", "tcp"))
        self.labelTLSPort.setText(_translate("DNSDialog", "Port"))
        self.editTLSPort.setPlaceholderText(_translate("DNSDialog", "e.g., 443"))
        self.editTLSPort.setText(_translate("DNSDialog", "443"))
        self.labelTLSCertUsage.setText(_translate("DNSDialog", "Cert. Usage"))
        self.editTLSCertUsage.setPlaceholderText(_translate("DNSDialog", "e.g., 2"))
        self.editTLSCertUsage.setText(_translate("DNSDialog", "2"))
        self.labelTLSSelector.setText(_translate("DNSDialog", "Selector"))
        self.editTLSSelector.setPlaceholderText(_translate("DNSDialog", "e.g., 1"))
        self.editTLSSelector.setText(_translate("DNSDialog", "1"))
        self.labelTLSMatchingType.setText(_translate("DNSDialog", "Matching Type"))
        self.editTLSMatchingType.setPlaceholderText(_translate("DNSDialog", "e.g., 0"))
        self.editTLSMatchingType.setText(_translate("DNSDialog", "0"))
        self.label_24.setText(_translate("DNSDialog", "Certificate Association Data (Base64)"))
        self.editTLSData.setPlaceholderText(_translate("DNSDialog", "e.g., MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEURoQKhqi6Sghol6CAPyw/YgO4tK1IrAkWe/QT1VouB9toJSBmR7BxmsIPS+OAaFwaLNhyV5K4cAED8HZTaYwWQ=="))
        self.btnTLSCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabTLS), _translate("DNSDialog", "TLS"))
        self.labelSRVDesc.setText(_translate("DNSDialog", "Used to identify hosts that support particular services (e.g., IMAP, POP, SMTP, XMPP, Matrix, or Mumble). In the host field, absolute domain names must end with a dot (.)."))
        self.labelSRVPriority.setText(_translate("DNSDialog", "Priority"))
        self.editSRVPriority.setPlaceholderText(_translate("DNSDialog", "e.g., 10"))
        self.labelSRVWeight.setText(_translate("DNSDialog", "Weight"))
        self.editSRVWeight.setPlaceholderText(_translate("DNSDialog", "e.g., 100"))
        self.labelSRVPort.setText(_translate("DNSDialog", "Port"))
        self.editSRVPort.setPlaceholderText(_translate("DNSDialog", "e.g., 443"))
        self.labelSRVHost.setText(_translate("DNSDialog", "Host"))
        self.editSRVHost.setPlaceholderText(_translate("DNSDialog", "e.g., namecoin.bit."))
        self.btnSRVCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabSRV), _translate("DNSDialog", "SRV"))
        self.labelTXTDesc.setText(_translate("DNSDialog", "TXT records are used to associate a string of text with a hostname. These are primarily used for verification.\n"
"\n"
""))
        self.editTXTData.setPlaceholderText(_translate("DNSDialog", "Paste text string here"))
        self.btnTXTCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabTXT), _translate("DNSDialog", "TXT"))
        self.labelIMPORTDesc.setText(_translate("DNSDialog", "Imports specified entries from another Namecoin name and merges with the current one. Optionally, import entries and associate them with a designated subdomain."))
        self.labelIMPORTName.setText(_translate("DNSDialog", "Namecoin Name"))
        self.editIMPORTName.setPlaceholderText(_translate("DNSDialog", "e.g., d/othername"))
        self.labelIMPORTSubdomain.setText(_translate("DNSDialog", "Subdomain (optional)"))
        self.editIMPORTSubdomain.setPlaceholderText(_translate("DNSDialog", "e.g., www"))
        self.btnIMPORTCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabIMPORT), _translate("DNSDialog", "IMPORT"))
        self.labelSSHFPDesc.setText(_translate("DNSDialog", "SSH records are used to identify an SSH server fingerprint associated with a domain."))
        self.labelSSHFPAlgorithm.setText(_translate("DNSDialog", "Algorithm"))
        self.editSSHFPAlgorithm.setPlaceholderText(_translate("DNSDialog", "e.g., 2"))
        self.labelSSHFPFingerprintType.setText(_translate("DNSDialog", "Fingerprint Type"))
        self.editSSHFPFingerprintType.setPlaceholderText(_translate("DNSDialog", "e.g., 1"))
        self.labelSSHFPFingerprint.setText(_translate("DNSDialog", "Fingerprint (Base64)"))
        self.editSSHFPFingerprint.setPlaceholderText(_translate("DNSDialog", "e.g., EjRWeJq83vZ4kBI0VniavN72eJA="))
        self.btnSSHFPCreate.setText(_translate("DNSDialog", "Create Record"))
        self.tabRecords.setTabText(self.tabRecords.indexOf(self.tabSSHFP), _translate("DNSDialog", "SSH"))
        self.labelDNSRecords.setText(_translate("DNSDialog", "DNS records"))
        self.totalSize.setText(_translate("DNSDialog", "Total Size (Bytes)"))
        self.labelOfTotal.setText(_translate("DNSDialog", "/ 520"))
        self.btnDeleteRecord.setText(_translate("DNSDialog", "Delete Record"))
        self.btnEditRecord.setText(_translate("DNSDialog", "Edit Record"))
from .qvalidatedlineedit import QValidatedLineEdit


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    DNSDialog = QtWidgets.QDialog()
    ui = Ui_DNSDialog()
    ui.setupUi(DNSDialog)
    DNSDialog.show()
    sys.exit(app.exec_())