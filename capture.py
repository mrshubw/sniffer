"""捕获底层数据包，传给数据model"""

import typing

from PyQt5.QtCore import QObject, QThread, pyqtSignal
from scapy.all import *

from model import *


class Capturer(QThread):
    captureSignal = pyqtSignal(object, list)

    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.parser = Parser(PacketsModel.header)

        self.filter = None
        self.iface = "WLAN"

    def run(self) -> None:
        sniff(filter=self.filter, prn=lambda packet:self.callBack(packet), iface=self.iface, count=0)

    def callBack(self, packet: typing.Optional[Packet]):
        self.captureSignal.emit(packet, self.parser.parse(packet))
        # ls(packet)
        layer = packet
        while layer:
            print(layer)
            layer = layer.payload.getlayer()
        print("*****************************************")
        

class Parser(QObject):
    """解析捕获的数据包"""
    def __init__(self, format: list, parent: typing.Optional['QObject'] = None) -> None:
        super().__init__(parent)
        self.format = format
        self.packetNo = 0

    def parse(self, packet: typing.Optional[Packet]) -> list:
        """解析出需要提取的包数据组成列表"""
        self.packetNo += 1
        output = []
        for content in self.format:
            if content is "No":
                output.append(str(self.packetNo))
            elif content is "Time":
                time_tuple = time.localtime(time.time())
                output.append("{}:{}:{}".format(time_tuple[3],time_tuple[4],time_tuple[5]))
            elif content is "Source":
                output.append(packet["IP"].src)
            elif content is "Destination":
                output.append(packet["IP"].dst)
            elif content is "Protocol":
                output.append(packet["IP"].proto)
            else:
                output.append(None)
        return output