"""嗅探器的整体实现，提供外部接口"""

import sys
import typing

from PyQt5.QtCore import QObject, QSortFilterProxyModel, QThread, QRegExp
from PyQt5.QtWidgets import QApplication

from capture import *
from model import *
from view import *


class Sniffer(QObject):
    def __init__(self, parent: typing.Optional['QObject'] = None) -> None:
        super().__init__(parent)
        self.capturer = Capturer()
        self.parser = Parser(PacketsModel.header)
        self.packetsModel = PacketsModel()
        self.filterModel = QSortFilterProxyModel()
        self.window = SnifferWindow()
        self.window.setIfaces(getIfacesFromRoute())
        
        self.captureThread = QThread()
        self.captureThread.start()
        self.capturer.moveToThread(self.captureThread)

        self.filterModel.setSourceModel(self.packetsModel)
        self.window.setModel(self.filterModel)
        self.window.setCapturer(self.capturer)
        self.parser.parseSignal.connect(self.packetsModel.addPacket)
        self.capturer.captureSignal.connect(self.parser.handle)
        self.window.showFilterSignal.connect(self.showFilter)

    def showFilter(self, filterString):
        self.filterModel.setFilterRegExp(QRegExp(filterString, Qt.CaseInsensitive, QRegExp.FixedString))
        self.filterModel.setFilterKeyColumn(6)

    def show(self):
        self.window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = Sniffer()
    sniffer.show()
    sys.exit(app.exec_())
