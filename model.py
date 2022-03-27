"""存储数据，对外展示，提供过滤操作"""

import typing

from PyQt5.QtCore import (QAbstractTableModel, QModelIndex, QObject, Qt, QAbstractItemModel,
                          QVariant)


class PacketsModel(QAbstractTableModel):
    """存储嗅探到的数据包的模型"""
    header = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.packets = []  # 存储数据包
        self.parsePackets = []  # 解析成header格式
        self.packetsBuffer = []
        self.parsePacketsBuffer = []

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
            return self.parsePackets[index.row()][index.column()]
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
            self.parsePackets.insert(i, self.parsePacketsBuffer[i-row])
        self.endInsertRows()
        return True

    def removeRows(self, row: int, count: int, parent: QModelIndex = QModelIndex()) -> bool:
        return super().removeRows(row, count, parent)

    def addPacket(self, packet, parsePacket):
        self.packetsBuffer = [packet]
        self.parsePacketsBuffer = [parsePacket]
        self.insertRows(self.rowCount(), 1)

    def getPacket(self, index):
        return self.packets[index]

    def setSource(self, source):
        """设置模型的数据源"""
        source.captureSignal.connect(self.addPacket)


class ParseModel(QAbstractItemModel):
    """呈现数据包的解析结构"""
    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)