"""存储数据，对外展示，提供过滤操作"""

import typing

from PyQt5.QtCore import (QAbstractItemModel, QAbstractTableModel, QModelIndex,
                          QObject, Qt, QVariant)
from PyQt5.QtGui import QColor


class PacketsModel(QAbstractTableModel):
    """存储嗅探到的数据包的模型"""
    header = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
    protocolColor = {"Ethernet":"#000000", "IP":"#ff0000", "TCP": "#00ff00", "UDP":"#0000ff", "ARP":"#aa0000", "ICMP": "#00aa00", "DNS": "#0000aa", "HTTP":"#849567", "IPv6": "#624896"}

    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.packets = []  # 存储数据包
        self.headerPackets = []  # 解析成header格式
        self.treePackets = []  # 解析成tree格式
        self.packetsBuffer = []
        self.headerPacketsBuffer = []
        self.treePacketsBuffer = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.packets)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.header)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> typing.Any:
        if not index.isValid():
            return QVariant()

        if index.row() >= len(self.packets):
            return QVariant()

        if index.column() >= len(self.header):
            return QVariant()

        if role == Qt.DisplayRole:
            return self.headerPackets[index.row()][index.column()]
        elif role == Qt.BackgroundColorRole:
            try:
                return QColor(self.protocolColor[self.headerPackets[index.row()][4]])
            except:
                return QColor(Qt.white)
        else:
            return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> typing.Any:
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            return self.header[section]
        else:
            return QVariant()

    def insertRows(self, row: int, count: int, parent: QModelIndex = QModelIndex()) -> bool:
        self.beginInsertRows(parent, row, row+count)
        for i in range(row, row+count):
            self.packets.insert(i, self.packetsBuffer[i-row])
            self.headerPackets.insert(i, self.headerPacketsBuffer[i-row])
            self.treePackets.insert(i, self.treePacketsBuffer[i-row])
        self.endInsertRows()
        return True

    def removeRows(self, row: int, count: int, parent: QModelIndex = QModelIndex()) -> bool:
        self.beginRemoveRows(parent, row, row+count)
        del self.packets[row:row+count]
        del self.headerPackets[row:row+count]
        del self.treePackets[row:row+count]
        self.endRemoveRows()
        return True

    def addPacket(self, packet, headerPacket, treePacket):
        self.packetsBuffer = [packet]
        self.headerPacketsBuffer = [headerPacket]
        self.treePacketsBuffer = [treePacket]
        self.insertRows(self.rowCount(), 1)

    def getPacket(self, index):
        return self.packets[index], self.treePackets[index]

    def clear(self):
        self.removeRows(0, self.rowCount())


class ParseModel(QAbstractItemModel):
    """呈现数据包的解析结构"""
    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)
