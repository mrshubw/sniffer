"""捕获底层数据包，传给数据model"""

import typing

from PyQt5.QtCore import QCoreApplication, QObject, pyqtSignal
from scapy.all import *
import re


def getIfacesFromRoute():
    output = []
    for net, msk, gw, iface, addr, metric in conf.route.routes:
        if_repr = resolve_iface(iface).description
        output.append(if_repr)
    return list(set(output))


def getIfaces():
    output = []
    for iface_name in sorted(conf.ifaces.data):
        dev = conf.ifaces.data[iface_name]
        prov = dev.provider
        output.append(prov._format(dev)[1])
    return list(set(output))


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
            sniff(filter=self.filter, prn=self.callBack, iface=self.iface, count=1, timeout=5)
            QCoreApplication.processEvents()

    def callBack(self, packet: typing.Optional[Packet]):
        self.packetNo += 1
        nowTime = time.localtime(time.time())
        rcvTime = "{}:{}:{}".format(nowTime[3], nowTime[4], nowTime[5])
        self.captureSignal.emit(packet, self.packetNo, rcvTime)
        # ls(packet)
        #print(str(packet))
        #print("*****************************************")

    def start(self, iface: str =None, filter_: str =None):
        self.iface = self.iface if iface is None else iface
        self.filter = self.filter if filter_ is None else filter_
        if not self.running:
            self.running = True
            self.run()
    
    def end(self):
        self.running = False
        

class Parser(QObject):
    parseSignal= pyqtSignal(object, list, dict)

    flag = {"RRG":0x20, "ACK":0x10, "PSH":0x08, "RST":0x04, "SYN":0x02, "FIN":0x01}


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
        ptn = re.compile(r"^\s*(\w+)\s*=\s(.*)$", re.M)
        while layer:
            self.treePacket[layer.name] = {}
            rep = layer.show(dump=True)
            index_list = [i.start() for i in re.finditer(r"###\[", rep)] 
            endpos = index_list[1] if len(index_list)>1 else len(rep)
            res = ptn.findall(rep, 0, endpos)
            for f in range(len(res)):
                self.treePacket[layer.name][res[f][0]] = res[f][1]

            if layer.name is "Ethernet":
                self.parseEthernet(layer)
            elif layer.name is "IP":
                self.parseIP(layer)
            elif layer.name is "ARP":
                self.parseARP(layer)
            elif layer.name is "IPv6":
                self.parseIPv6(layer)
            elif layer.name is "TCP":
                self.parseTCP(layer)
            elif layer.name is "UDP":
                self.parseUDP(layer)
            elif layer.name is "ICMP":
                self.parseICMP(layer)
            elif layer.name is "DNS":
                self.parseDNS(layer)
            else:
                self.parseHttp(layer)

            layer = layer.payload

    def parseEthernet(self, layer):
        """解析以太层"""
        self.headerPacket["Protocol"] = layer.name
        pass

    def parseIP(self, layer):
        """解析IP层"""
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.src
        self.headerPacket["Destination"] = layer.dst
        info = ""
        info = "{}->{}".format(layer.src, layer.dst)
        self.headerPacket["Info"] = info
        pass

    def parseARP(self, layer):
        """解析ARP层"""
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.psrc
        self.headerPacket["Destination"] = layer.pdst
        info = ""
        if layer.op == 1:
            info += "Who has {}? Tell {}".format(layer.pdst, layer.psrc)
        elif layer.op ==2:
            info += "{} is at {}".format(layer.psrc, layer.hwsrc)
        self.headerPacket["Info"] = info

    def parseIPv6(self, layer):
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.psrc
        self.headerPacket["Destination"] = layer.pdst
        info = ""
        info = "{}->{}".format(layer.src, layer.dst)
        self.headerPacket["Info"] = info
    
    def parseTCP(self, layer):
        """解析TCP层"""
        self.headerPacket["Protocol"] = layer.name
        info = "{}->{} ".format(layer.sport, layer.dport)
        flagList = []
        for i in self.flag:
            if layer.flags&self.flag[i]:
                flagList.append(i)
        info += "["+", ".join(flagList)+"]"
        info += " Seq={} Ack={} Win={}".format(layer.seq, layer.ack, layer.window)
        self.headerPacket["Info"] = info
        pass
    
    def parseUDP(self, layer):
        """解析UDP层"""
        self.headerPacket["Protocol"] = layer.name
        info = "{}->{}".format(layer.sport, layer.dport)
        info += " Len={}".format(layer.len)
        self.headerPacket["Info"] = info
        pass
    
    def parseICMP(self, layer):
        """解析ICMP层"""
        self.headerPacket["Protocol"] = layer.name
        info = ""
        if layer.type == 8:
            info += "Echo (ping) request "
        elif layer.type == 0:
            info += "Echo (ping) reply "
        info += "id={},seq={},ttl={}".format(layer.id, layer.seq, self.treePacket["IP"]["ttl"])
        self.headerPacket["Info"] = info
    
    def parseDNS(self, layer):
        """解析DNS层"""
        self.headerPacket["Protocol"] = layer.name
        info = ""
        rep = sane(bytes_encode(layer))
        res = re.search(r"\w+(\.\w+)+", rep)
        info += res.group()
        self.headerPacket["Info"] = info
        pass

    def parseHttp(self, layer):
        httpFormat = "((GET|POST|CONNECT).*HTTP/[\d\.]+)"
        searchObj = re.search(httpFormat, str(raw(layer[0])))
        if searchObj is not None:
            self.headerPacket["Protocol"] = "HTTP"
            self.headerPacket["Info"] = searchObj.group()
            return True
        return False

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

    def handle(self, packet: typing.Optional[Packet], packetNo: int, rcvTime: str):
        """槽函数，接受捕获的包，解析并传给存储模型"""
        try:
            self.parseSignal.emit(packet, self.headerParse(packet, packetNo, rcvTime), self.treeParse(packet))
        except Exception as e:
            print(e)
