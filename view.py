"""用户窗口"""

import typing

from PyQt5 import QtCore
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QComboBox, QHBoxLayout, QLineEdit, QPushButton,
                             QSplitter, QTableView, QTextEdit, QTreeWidget,
                             QTreeWidgetItem, QVBoxLayout, QWidget, QHeaderView)
from scapy.all import *

RESOURCES_DIR = "./resources/"


class SnifferWindow(QWidget):
    startSignal = pyqtSignal(str, str)
    showFilterSignal = pyqtSignal(str)

    def __init__(self, parent: typing.Optional['QWidget'] = None, flags: typing.Union[QtCore.Qt.WindowFlags, QtCore.Qt.WindowType] = Qt.Widget) -> None:
        super().__init__(parent, flags)
        self.resize(1200, 800)
        self.setWindowTitle("嗅探器")
        self.setWindowIcon(QIcon(RESOURCES_DIR+"sniffer.png"))
        self.__setUpUI()
        self.__setUpConnect()
        
    def __setUpUI(self):
        """设置窗口组件"""
        self.ifaceSelect = QComboBox()
        self.ifaceSelect.setToolTip("select network interface")
        self.ifaceSelect.setMaximumWidth(400)
        self.sourceFilterBox = QLineEdit()
        self.sourceFilterBox.setToolTip("set source filter")
        self.showFilterBox = QLineEdit()
        self.showFilterBox.setToolTip("set show filter")
        self.startButton = QPushButton(QIcon(RESOURCES_DIR+"start.png"), None)
        self.startButton.setFlat(True)
        self.startButton.setToolTip("start")
        self.endButton = QPushButton(QIcon(RESOURCES_DIR+"end.png"), None)
        self.endButton.setFlat(True)
        self.endButton.setToolTip("end")
        self.clearButton = QPushButton(QIcon(RESOURCES_DIR+"clear.png"), None)
        self.clearButton.setFlat(True)
        self.clearButton.setToolTip("clear")
        layoutHeader = QHBoxLayout()
        layoutHeader.addWidget(self.ifaceSelect)
        layoutHeader.addWidget(self.sourceFilterBox)
        layoutHeader.addWidget(self.showFilterBox)
        layoutHeader.addWidget(self.startButton)
        layoutHeader.addWidget(self.endButton)
        layoutHeader.addWidget(self.clearButton)
        layoutHeader.setStretch(0, 1)
        layoutHeader.setStretch(1, 1)
        layoutHeader.setStretch(2, 1)
        layoutHeader.setStretch(3, 0)
        layoutHeader.setStretch(4, 0)
        layoutHeader.setStretch(5, 0)
        layoutHeader.addStretch(1)
    
        self.packetsView = QTableView()
        #self.packetsView.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        #self.packetsView.resizeColumnsToContents()

        self.treeShow = QTreeWidget()
        self.treeShow.setColumnCount(2)
        self.treeShow.setHeaderLabels(["field", "value"])
        self.hexdumpShow = QTextEdit()
        self.hexdumpShow.setReadOnly(True)
        self.splitterShow = QSplitter()
        self.splitterShow.addWidget(self.treeShow)
        self.splitterShow.addWidget(self.hexdumpShow)

        self.splitterMain = QSplitter(Qt.Vertical)
        self.splitterMain.addWidget(self.packetsView)
        self.splitterMain.addWidget(self.splitterShow)

        layout = QVBoxLayout()
        layout.addLayout(layoutHeader)
        layout.addWidget(self.splitterMain)
        self.setLayout(layout)

    def __setUpConnect(self):
        """设置窗口间的信号连接"""
        self.startButton.clicked.connect(self.start)

    def start(self):
        self.startSignal.emit(str(self.ifaceSelect.currentText()), self.sourceFilterBox.text())
        self.showFilterSignal.emit(self.showFilterBox.text())

    def transferCurrentPacket(self):
        """点击视图，显示当前包详情"""
        row = self.packetsView.currentIndex().row()
        packet, treePacket = self.packetsView.model().sourceModel().getPacket(row)

        self.treeShow.clear()
        for layer in treePacket:
            layerItem = QTreeWidgetItem(self.treeShow)
            layerItem.setText(0, layer)
            for field in treePacket[layer]:
                fieldItem = QTreeWidgetItem(layerItem)
                fieldItem.setText(0, field)
                fieldItem.setText(1, treePacket[layer][field])

        self.hexdumpShow.setText(hexdump(packet, True))

    def setModel(self, model):
        self.packetsView.setModel(model)
        self.packetsView.clicked.connect(self.transferCurrentPacket)
        self.clearButton.clicked.connect(model.sourceModel().clear)

    def setCapturer(self, source):
        self.packetsView.setColumnWidth(6, 400)
        self.startSignal.connect(source.start)
        self.endButton.clicked.connect(source.end)

    def setIfaces(self, ifaces: list):
        self.ifaceSelect.addItems(ifaces)
