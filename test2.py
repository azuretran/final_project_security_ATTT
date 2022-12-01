from scapy.all import *

scapy_cap = rdpcap('abc.pcap')
print(dir(scapy_cap[0].show()))
""" print((scapy_cap.show()))  """
#!/usr/bin/python
""" from scapy.all import *

def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

sniff(iface='VMware Network Adapter VMnet8', prn=http_header, filter="tcp port 80")#!/usr/bin/python
from scapy.all import *

def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

sniff(iface='VMware Network Adapter VMnet8', prn=http_header, filter="tcp port 80") """