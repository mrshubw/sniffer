import sys
import typing

import scapy
from PyQt5 import QtCore
from PyQt5.QtCore import QObject, QAbstractTableModel, QModelIndex, Qt, QVariant
from PyQt5.QtGui import QPainter
from PyQt5.QtWidgets import QApplication, QWidget


class PacketsModel(QAbstractTableModel):
    """存储嗅探到的数据包的模型"""
    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.packets = []  # 存储数据包

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return super().rowCount(parent)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return super().columnCount(parent)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> typing.Any:
        if not index.isValid():
            return QVariant()

        if index.row() >= len(self.packets):
            return QVariant()

        if role == Qt.DisplayRole:
            return self.packets[index.row()]
        else:
            return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> typing.Any:
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            return "Column %s" % section
        else:
            return "Row %s" % section


class SnifferWindow(QWidget):
    def __init__(self, parent: typing.Optional['QWidget'] = None, flags: typing.Union[QtCore.Qt.WindowFlags, QtCore.Qt.WindowType] = Qt.Widget) -> None:
        super().__init__(parent, flags)


class Sniffer(QObject):
    def __init__(self, parent: typing.Optional['QObject'] = None) -> None:
        super().__init__(parent)
        self.window = SnifferWindow()

    def show(self):
        self.window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = Sniffer()
    sniffer.show()
    sys.exit(app.exec_())
