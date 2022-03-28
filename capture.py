"""捕获底层数据包，传给数据model"""

import typing

from PyQt5.QtCore import QObject, pyqtSignal, QCoreApplication
from scapy.all import *


def getIfacesFromRoute():
    output = []
    for net, msk, gw, iface, addr, metric in conf.route.routes:
        if_repr = resolve_iface(iface).description
        output.append(if_repr)
    return output


def getIfaces():
    output = []
    for iface_name in sorted(conf.ifaces.data):
        dev = conf.ifaces.data[iface_name]
        prov = dev.provider
        output.append(prov._format(dev)[1])
    return output


class Capturer(QObject):
    captureSignal = pyqtSignal(object, int, str)

    def __init__(self, parent: typing.Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.packetNo = 0
        self.running = False

        self.filter = None
        self.iface = "WLAN"

    def run(self) -> None:
        while self.running:
            sniff(filter=self.filter, prn=lambda packet:self.callBack(packet), iface=self.iface, count=1)
            QCoreApplication.processEvents()

    def callBack(self, packet: typing.Optional[Packet]):
        self.packetNo += 1
        nowTime = time.localtime(time.time())
        rcvTime = "{}:{}:{}".format(nowTime[3], nowTime[4], nowTime[5])
        self.captureSignal.emit(packet, self.packetNo, rcvTime)
        # ls(packet)
            
        print("*****************************************")

    def start(self):
        if not self.running:
            self.running = True
            self.run()

    def end(self):
        self.running = False
        

class Parser(QObject):
    parseSignal= pyqtSignal(object, list, dict)

    """解析捕获的数据包"""
    def __init__(self, format: list, parent: typing.Optional['QObject'] = None) -> None:
        super().__init__(parent)
        self.format = format
        self.packetNo = 0
        self.packet = None
        self.headerPacket = dict.fromkeys(self.format)
        self.treePacket = {}

    def parse(self, packet: typing.Optional[Packet]):
        """解析出需要提取的包数据组成列表"""
        self.packet = packet
        self.headerPacket = dict.fromkeys(self.format)
        self.treePacket = {}
        self.packetNo += 1

        layer = packet
        while layer:
            self.treePacket[layer.name] = {}
            for f in layer.fields_desc:
                fvalue = packet.getfieldval(f.name)
                reprval = f.i2repr(packet, fvalue)
                self.treePacket[layer.name][f.name] = reprval

            if layer.name is "Ethernet":
                self.parseEthernet(layer)
            elif layer.name is "IP":
                self.parseIP(layer)
            elif layer.name is "ARP":
                self.parseARP(layer)
            elif layer.name is "TCP":
                self.parseTCP(layer)
            elif layer.name is "UDP":
                self.parseUDP(layer)
            elif layer.name is "ICMP":
                self.parseICMP(layer)
            elif layer.name is "DNS":
                self.parseDNS(layer)
            else:
                pass

            layer = layer.payload

        print(self.treePacket)

    def parseEthernet(self, layer):
        """解析以太层"""
        self.headerPacket["Protocol"] = layer.name
        pass

    def parseIP(self, layer):
        """解析IP层"""
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.src
        self.headerPacket["Destination"] = layer.dst
        pass

    def parseARP(self, layer):
        """解析ARP层"""
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.psrc
        self.headerPacket["Destination"] = layer.pdst
        pass
    
    def parseTCP(self, layer):
        """解析TCP层"""
        self.headerPacket["Protocol"] = layer.name
        pass
    
    def parseUDP(self, layer):
        """解析UDP层"""
        self.headerPacket["Protocol"] = layer.name
        pass
    
    def parseICMP(self, layer):
        """解析ICMP层"""
        self.headerPacket["Protocol"] = layer.name
        pass
    
    def parseDNS(self, layer):
        """解析DNS层"""
        self.headerPacket["Protocol"] = layer.name
        pass

    def headerParse(self, packet: typing.Optional[Packet], packetNo, rcvTime: str) -> list:
        if self.packet != packet:
            self.parse(packet)

        self.headerPacket["No"] = packetNo
        self.headerPacket["Time"] = rcvTime
        self.headerPacket["Length"] = len(packet)

        return list(self.headerPacket.values())

    def treeParse(self, packet: typing.Optional[Packet]) -> dict:
        if self.packet != packet:
            self.parse(packet)

        return self.treePacket

    def handle(self, packet: typing.Optional[Packet], packetNo, rcvTime: str):
        """槽函数，接受捕获的包，解析并传给存储模型"""
        self.parseSignal.emit(packet, self.headerParse(packet, packetNo, rcvTime), self.treeParse(packet))
