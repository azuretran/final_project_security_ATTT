'''
Viết chương trình python để chuyển một .pcap file thành .csv file

Viết chương trình python tự động thu thập lưu lượng trên một giao tiếp
mạng và xuất ra .csv file một cách liên tục.
'''

# Import thư viện scapy
from telnetlib import IP
from scapy.all import *
import pyshark
import time
pkts = rdpcap('file.pcap')
#xóa toàn bộ data file output ban đầu
open('output', 'w').close()
with open("output.csv", "w") as f:
     for pkt in pkts:

        if IP in pkt:
            ip_src=pkt[IP].src
            ip_dst=pkt[IP].dst
        if TCP in pkt:
            tcp_dport=pkt[TCP].dport
            x=pkt[TCP].options
            
            csv_header = "IP_src,\tIP_drc,dst_port\n"

            s = ""
            for scr in str(ip_src):
                s+=str(scr)
            csv_header += s + ','

            s_ = ''
            for dst in str(ip_dst) :
                s_+=str(dst)
            csv_header += s_ + ','

            s_1 = ''
            for dst_tcp in str(tcp_dport):
                s_1 += str(dst_tcp)
            csv_header += s_1
            s_2=''
            for dst_tcp in str(x):
                s_2 += str(dst_tcp)
            csv_header += s_2

            f.write(csv_header) 
    
""" #bài 2 
# đặt card mạng chính là ethernet
networkInterface = "VMware Network Adapter VMnet8"

# xác định đối tượng capture
capture = pyshark.LiveCapture(interface=networkInterface)
print("listening on %s" % networkInterface)
s = ""
with open('outbai2.csv','w') as f:
    for packet in capture.sniff_continuously(packet_count=1000):
        # điều chỉnh giá trị in ras
        try:
            # xác định dấu thời gian
            localtime = time.asctime(time.localtime(time.time()))
        
            # lấy nội dung packet
            protocol = packet.transport_layer   
            src_addr = packet.ip.src           
            src_port = packet[protocol].srcport  
            dst_addr = packet.ip.dst           
            dst_port = packet[protocol].dstport   
            
            #thông tin đầu ra
            print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
            s = "%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol)+'\n'
            f.write(s)
        except AttributeError as e:
            #bỏ packet khác   UDP and IPv4
            pass
        print (" ")
 """