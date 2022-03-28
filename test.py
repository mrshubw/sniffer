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

print(getIfacesFromRoute())
