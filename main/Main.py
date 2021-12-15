from scapy.config import conf
from scapy.packet import ls
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.themes import BrightTheme
from queue import Queue
import threading
from control.Control import Control
import time


class Main(object):
    """循环调用其它组件的模块

    这个类生成两个新进程。
    1号进程持续抓包，并将包塞入队列(__packet_que)中。
    2号进程不断询问队列是否有新的未处理的包，若存在则直接开始处理。
    当前进程允许用户输入，以便进行对局域网内主机的控制

    Attributes:
        __packet_que: 队列，用于存放未被处理的包
        log: 指定是否要打印所有抓到的包的summary
    """

    __packet_que: Queue
    log: bool

    def __init__(self, log=True, maxsize=1024):
        """指定队列长度"""
        self.log = log
        self.__pack_que = Queue(maxsize=maxsize)

    def getPacket(self):
        """抓取数据包"""
        print("Starting getting packets")
        while True:
            packet = sniff(count=1) # 抓
            packet = packet[0]
            self.__pack_que.put(packet)

    def polling(self):
        """循环处理当前队列，如果有包则进行处理"""
        while True:
            if self.__pack_que.not_empty:
                packet = self.__pack_que.get()

                if self.log: print(packet.summary())

                # TODO decipher
                # if decipher.isEncrypted(packet):
                #     packet = decipher(packet)

                # TODO statistic
                # statistic(packet)

    def start(self, type='master'):
        # for example:
        # statistic = Statistic()
        control = Control()
        # decipher  = Decipher()

        if type == 'slave':
            control.as_a_slave()
            print('listening...')
            while True:
                time.sleep(10)

        elif type == 'master':
            "启动抓包"
            threading_getPacket = threading.Thread(target=self.getPacket)
            threading_getPacket.daemon = True
            threading_getPacket.start()
            "启动包处理程序"
            threading_polling = threading.Thread(target=self.polling)
            threading_polling.daemon = True
            threading_polling.start()

            while True:
                """
                控制界面
                输入格式:
                warning <host> <message> 警告host，在对方主机显示字符串message
                disconnection <host> 对host断网
                connection <host> 恢复host联网状态
                restart 恢复所有主机
                """
                print("输入格式:\n"
                      "warning <host> <message>\n"
                      "Disconnection <host>\n"
                      "connection <host>\n"
                      "restart 恢复所有主机")

                opt = input().strip().split()
                if len(opt) == 3 and opt[0] == 'warning':
                    control.warning(opt[1], opt[2])
                    print('警告已发送')

                elif len(opt) == 2 and opt[0] == 'disconnection':
                    control.disconnection(opt[1])
                    print(opt[1] + '已被断网')

                elif len(opt) == 2 and opt[0] == 'connection':
                    control.connection(opt[1])
                    print(opt[1] + '已恢复连接')

                elif len(opt) == 1 and opt[0] == 'restart':
                    control.connection_all()
                    print('恢复成功')

