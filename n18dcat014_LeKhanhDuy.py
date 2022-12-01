from scapy.all import Ether, srp, sniff, conf, TCP, IP
from datetime import datetime, date


count_1 = 0
count_2 = 0
count_3 = 0
count_4 = 0
count_5 = 0
count_atk = 0

attacker_ip = ''
attacker_port = []

victim_ip = ''
victim_port = []


def process(packet):
    global count_atk, count_1, count_2, count_3, count_4, count_5, attacker_ip, attacker_port, victim_ip, victim_port
    if packet.haslayer(TCP):
        try:
            src = packet[IP].src
            dst = packet[IP].dst

            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            window = packet[TCP].window

            if flags == 'S' and window == 64240:  # Attacker-> Victim
                count_1 = 1
                attacker_ip = src
                victim_ip = dst
                attacker_port.append(sport)
                victim_port.append(dport)

            if flags == 'SA' and window == 28960:  # Victim -> Attacker
                count_2 = 1
                attacker_port.append(dport)
                victim_port.append(sport)

            if flags == 'S' and window == 29200:  # Attacker-> Victim
                count_3 = 1
                attacker_port.append(sport)
                victim_port.append(dport)

            if flags == 'SA' and window == 65160:  # Victim -> Attacker
                count_4 = 1
                attacker_port.append(dport)
                victim_port.append(sport)

            if flags == 'A' and window == 510:
                count_5 += 1

            print(count_5)
            if count_1 and count_2 and count_3 and count_4 and count_5 > 800:
                now = datetime.now()

              # print('Cảnh báo!! Đang bị khai thác lỗ hổng CVE-2018-15708')
              # print(now, ' || ', attacker_ip, '=>', victim_ip, '\n')

                count_atk += 1
                while count_atk > 0:
                    with open('listfile.csv', 'a') as filehandle:
                        # s = str(now) + ' | ' + str(attacker_ip) + \
                        #     ' : ' + str(attacker_port) + '\n'

                        s = str(attacker_port) + str(victim_port) + '\n'
                        filehandle.write(s)
                    count_atk -= 1

                count_1 = 0
                count_2 = 0
                count_3 = 0
                count_4 = 0
                count_5 = 0
                attacker_ip = ''
                attacker_port = []
                victim_ip = ''
                victim_port = []

        except IndexError:
            pass


if __name__ == "__main__":
    # Sử dụng live capture
    sniff(store=False, prn=process, iface='VMware Network Adapter VMnet8')

    # Sử dụng file pcap để test
    # sniff(store=False, prn=process, offline='data_test.pcap')
