
        
'''
Hướng dẫn:
-Dựa vào phân tích các bước trong cuộc tấn công lấy signature đặc trưng của tấn công
-Sử dụng kết quả buổi 6 để thu thập brute force data
-Viết code dò signature trong brute force data để phát hiện

Yêu cầu: Mở chương trình phát hiện chạy thường trực. Khi tiến hành cuộc tấn công brute force vào FTP server, chương trình phát hiện sẽ phát cảnh báo.
'''
import pyshark,csv
import subprocess
'''


'''

counter=0
lasttime=0
first=0

def get_packet():
        #cài windump vào máy và chạy file filesss pcap (là file đã thu thập được khi brute force)
        command = "WinDump.exe -i 6 -n -c 1000 -w filess.pcap"
        subprocess.call(command)
def rm_packet():
        command = "filess.pcap"
        subprocess.call(command)



def save_csv():
        fieldnames = ['No', 'Times','Timesstamp', 'Source','Destination','Message']
        capture = pyshark.FileCapture('filess.pcap')
        capture.load_packets()
        capture.reset()
        with open('filecapture.csv', 'w') as csv_file:
                writer = csv.writer(csv_file, delimiter=',',lineterminator='\n')
                writer.writerow(fieldnames)
                for item in capture:
                        if 'ftp' in item:
                                writer.writerow([item.number,item.sniff_time,item.sniff_timestamp,item.ip.src_host,item.ip.dst_host,str(item.ftp).encode()])
                        if 'tcp' in item:
                                writer.writerow([item.number,item.sniff_time,item.sniff_timestamp,item.ip.src_host,item.ip.dst_host,str(item.tcp).encode()])

def detect_ftp_bruteforce(item):
        global lasttime,counter
        if 'Login incorrect' in item[5]:
                #print (float(item.sniff_timestamp)-lasttime)
                if float(item[2])-lasttime<5:
                        lasttime=float(item[2])
                        counter+=1
                if counter > 4:
                        print ('==============^===============')
                        print ('Phát hiện tấn công Brute force')
                        print ('Thời gian : '+item[1])
                        print ('IP src: '+item[3])
                        print ('IP des: '+item[4])
                        lasttime=float(item[2])
                        counter=0


def read_csv():
        global lasttime,first
        with open('filecapture.csv') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if 'FTP' in row[5]:
                        if first==0:
                                lasttime=float(row[2])
                                first=1
                        detect_ftp_bruteforce(row)
            print(f'Processed {line_count} lines.')


while True:
        get_packet()
        save_csv()
        read_csv()
        
