from scapy.all import Ether, srp, sniff, conf, TCP, IP

count_1 = 0
count_2 = 0
count_3 = 0
count_4 = 0
count_5 = 0


attacker_ip = []
attacker_port = []


def process(packet):
    global count_1, count_2, count_3, count_4, count_5, attacker_ip, attacker_port
    if packet.haslayer(TCP):
        try:
            src = packet[IP].src
            dst = packet[IP].dst

            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            window = packet[TCP].window

            if flags == 'S' and window == 64240:
                count_1 = 1
                attacker_ip = src
                attacker_port.append(sport)

            if flags == 'SA' and window == 28960:
                count_2 = 1

            if flags == 'S' and window == 29200:
                count_3 = 1

            if flags == 'SA' and window == 65160:
                count_4 = 1

            if flags == 'A' and window == 510:
                count_5 += 1

        except IndexError:
            pass


if __name__ == "__main__":
    # sniff(store=False, prn=process, iface='VMware Network Adapter VMnet8')

    sniff(store=False, prn=process, offline='data_test.pcap')

    if count_1 and count_2 and count_3 and count_4 and count_5 > 1500:
        print("Đang bị tấn công bởi Attacker với IP: ", attacker_ip)
        count_1 = 0
        count_2 = 0
        count_3 = 0
        count_4 = 0
        count_5 = 0

    # print(attacker_port)

    with open('filecapture.csv', 'w') as csv_file:
        csv_file.write(attacker_ip)
