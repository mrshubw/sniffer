"""用户窗口"""

from ast import dump
from dbm import dumb
import typing
from scapy.all import *

from PyQt5 import QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import QWidget, QTableView, QVBoxLayout, QTextEdit, QHBoxLayout, QSplitter, QComboBox, QPushButton

RESOURCES_DIR = "./resources/"


class SnifferWindow(QWidget):
    def __init__(self, parent: typing.Optional['QWidget'] = None, flags: typing.Union[QtCore.Qt.WindowFlags, QtCore.Qt.WindowType] = Qt.Widget) -> None:
        super().__init__(parent, flags)
        self.resize(1200, 800)
        self.__setUpUI()
        
    def __setUpUI(self):
        """设置窗口组件"""
        self.ifaceSelect = QComboBox()
        self.ifaceSelect.setMaximumWidth(300)
        self.startButton = QPushButton(QIcon(QPixmap(RESOURCES_DIR+"start.png")), None)
        self.startButton.setFlat(True)
        self.startButton.setToolTip("start")
        self.endButton = QPushButton(QIcon(QPixmap(RESOURCES_DIR+"end.png")), None)
        self.endButton.setFlat(True)
        self.endButton.setToolTip("end")
        self.clearButton = QPushButton(QIcon(QPixmap(RESOURCES_DIR+"clear.png")), None)
        self.clearButton.setFlat(True)
        self.clearButton.setToolTip("clear")
        layoutHeader = QHBoxLayout()
        layoutHeader.addWidget(self.ifaceSelect)
        layoutHeader.addWidget(self.startButton)
        layoutHeader.addWidget(self.endButton)
        layoutHeader.addWidget(self.clearButton)
        layoutHeader.setStretch(0, 1)
        layoutHeader.setStretch(1, 0)
        layoutHeader.setStretch(2, 0)
        layoutHeader.setStretch(3, 0)
        layoutHeader.addStretch(1)
        


        self.packetsView = QTableView()

        self.textShow = QTextEdit()
        self.textHexdump = QTextEdit()
        self.splitterShow = QSplitter()
        self.splitterShow.addWidget(self.textShow)
        self.splitterShow.addWidget(self.textHexdump)

        self.splitterMain = QSplitter(Qt.Vertical)
        self.splitterMain.addWidget(self.packetsView)
        self.splitterMain.addWidget(self.splitterShow)

        layout = QVBoxLayout()
        layout.addLayout(layoutHeader)
        layout.addWidget(self.splitterMain)
        self.setLayout(layout)

    def transferCurrentPacket(self):
        """点击视图，显示当前包详情"""
        row = self.packetsView.currentIndex().row()
        packet = self.packetsView.model().getPacket(row)
        self.textShow.setText(packet.show(dump=True))
        self.textHexdump.setText(hexdump(packet, True))

    def setModel(self, model):
        self.packetsView.setModel(model)
        self.packetsView.clicked.connect(self.transferCurrentPacket)
        self.clearButton.clicked.connect(model.clear)

    def setCapturer(self, source):
        self.startButton.clicked.connect(source.start)
        self.endButton.clicked.connect(source.end)

    def setIfaces(self, ifaces: list):
        self.ifaceSelect.addItems(ifaces)