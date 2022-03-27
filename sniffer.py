"""嗅探器的整体实现，提供外部接口"""

import sys
import typing

from PyQt5.QtCore import QObject, QSortFilterProxyModel
from PyQt5.QtWidgets import QApplication

from capture import *
from model import *
from view import *


class Sniffer(QObject):
    def __init__(self, parent: typing.Optional['QObject'] = None) -> None:
        super().__init__(parent)
        self.capturer = Capturer()
        self.packetsModel = PacketsModel()
        self.filterModel = QSortFilterProxyModel()
        self.window = SnifferWindow()

        self.window.setModel(self.packetsModel)
        self.packetsModel.setSource(self.capturer)
        self.capturer.start()

    def show(self):
        self.window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = Sniffer()
    sniffer.show()
    sys.exit(app.exec_())
