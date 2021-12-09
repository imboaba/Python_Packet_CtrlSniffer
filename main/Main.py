from scapy.config import conf
from scapy.packet import ls
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.themes import BrightTheme
from queue import Queue
import threading


class Main(object):
    __packet_que : Queue
    log: bool

    def __init__(self, log=True, maxsize=1024):
        self.log = log
        self.__pack_que = Queue(maxsize=maxsize)


    def getPacket(self):
        print("Starting getting packets")
        while True:
            packet = sniff(count=1)
            packet = packet[0]
            self.__pack_que.put(packet)


    def start(self):
        # for example:
        # statistic = Statistic()
        # control   = control()
        # decipher  = Decipher()

        threading_tasks = threading.Thread(target=self.getPacket)
        threading_tasks.daemon = True
        threading_tasks.start()

        while True:
            if self.__pack_que.not_empty:
                packet = self.__pack_que.get()

                if self.log: print(packet.summary())

                # TODO decipher
                # if decipher.isEncrypted(packet):
                #     packet = decipher(packet)

                # TODO statistic
                # statistic(packet)

                # TODO SNMP
                # if packet.haslayer(UDP) and packet["UDP"].dport == 162:
                #     control(packet)

#
# if __name__ == '__main__':
#     conf.color_theme = BrightTheme()
#     main = Main()
#     main.start()

