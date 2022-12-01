from scapy.all import Ether, srp, sniff, conf, TCP, IP
import smtplib
import ssl
from email.message import EmailMessage



count_1 = 0
count_2 = 0
count_3 = 0
count_4 = 0
count_5 = 0


attacker_ip = []
attacker_port = []

def send_mail():
    email_sender = 'linhdautu@gmail.com'
    email_password = 'farzcbkoavahmgaq'
    email_receiver = 'n18dcat040@student.ptithcm.edu.vn'
# Define email sender and receiver
    # Set the subject and body of the email
    subject = 'Phát Hiện cuộc tấn công!'
    body = 'Đã phát hiện tấn công bởi cve 2017-0199'

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    # Add SSL (layer of security)
    context = ssl.create_default_context()

    # Log in and send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())
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

            if flags == 'PA' and window == 502:
                count_1 = 1
                attacker_ip = src
                attacker_port.append(sport)
           
            if count_1 :
                print("Đang bị tấn công cve 2017-0199 bởi Attacker với IP: ", attacker_ip)
                count_2=1
            if count_2:
                send_mail()
        except IndexError:
            pass



if __name__ == "__main__":

    sniff(store=False, prn=process, iface='VMware Network Adapter VMnet8')
    with open('filecapture.csv', 'w') as csv_file:
        csv_file.write(attacker_ip)
