import typing
import sys

import scapy
from PyQt5.QtCore import QObject
from PyQt5.QtGui import QPainter
from PyQt5.QtWidgets import QApplication, QWidget


class SnifferWindow(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)


class Sniffer(QObject):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.window = SnifferWindow()

    def show(self):
        self.window.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = Sniffer()
    sniffer.show()
    sys.exit(app.exec_())
