import ipaddress
import os
import socket
import struct
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication
from gui import Ui_MainWindow


# 创建 IP 结构体
class IP:
    def __init__(self, buffer=None):
        # 按照 IP 头结构格式提取信息
        header = struct.unpack('<BBHHHBBHII', buffer[0:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]
        self.data = buffer[20:65535]

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        '''
        58: 'ICMPv6', 2: 'IGMP'
        '''

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s 未找到协议代码： %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


# 创建 ICMP 结构体
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


class Box(Ui_MainWindow):
    def __init__(self, mainWindow):
        super().__init__()
        self.setupUi(mainWindow)

        self.textBrowser.setText('监听结果：')
        self.sniffPushButton.clicked.connect(self.sniff)

    def sniff(self):
        hostaddr = self.hostLineEdit.text()
        srcaddr = self.srcLineEdit.text()
        dstaddr = self.dstLineEdit.text()
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((hostaddr, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        # 一次监听10个IP数据包
        try:
            i = 0
            while i < 10:
                raw_buffer = sniffer.recvfrom(65535)[0]
                ip = IP(raw_buffer)

                # 实现 icmp 协议数据包过滤
                if self.icmpCheckBox.isChecked():
                    if ip.protocol == 'ICMP' or ip.protocol == 'ICMPv6':
                        self.textBrowser.append('协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                        self.textBrowser.append(f'版本号: {ip.ver}')
                        self.textBrowser.append(f'头部长度; {ip.ihl} 生存时间: {ip.ttl}')
                        offset = ip.ihl * 4
                        buf = raw_buffer[offset:offset + 8]
                        icmp = ICMP(buf)
                        self.textBrowser.append('ICMP -> Type: %s Code: %s\n' % (icmp.type, icmp.code))
                        self.textBrowser.append('')

                # 实现 tcp 和 udp 协议数据包过滤
                # 通过选择结构实现根据 IP 地址过滤
                if self.tcpCheckBox.isChecked():
                    if ip.protocol == 'TCP':
                        if srcaddr == '' and dstaddr == '':
                            self.textBrowser.append('协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                            self.textBrowser.append(str(ip.data))
                            self.textBrowser.append('')
                        elif srcaddr != '' and dstaddr == '':
                            if ip.src_address == srcaddr:
                                self.textBrowser.append(
                                    '协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                                self.textBrowser.append(str(ip.data))
                                self.textBrowser.append('')
                        elif dstaddr != '' and srcaddr == '':
                            if ip.dst_address == dstaddr:
                                self.textBrowser.append(
                                    '协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                                self.textBrowser.append(str(ip.data))
                                self.textBrowser.append('')
                        else:
                            if ip.dst_address == dstaddr and ip.src_address == srcaddr:
                                self.textBrowser.append(
                                    '协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                                self.textBrowser.append(str(ip.data))
                                self.textBrowser.append('')

                if self.udpCheckBox.isChecked():
                    if ip.protocol == 'UDP':
                        if srcaddr == '' and dstaddr == '':
                            self.textBrowser.append('协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                            self.textBrowser.append(str(ip.data))
                            self.textBrowser.append('')
                        elif srcaddr != '' and dstaddr == '':
                            if ip.src_address == srcaddr:
                                self.textBrowser.append(
                                    '协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                                self.textBrowser.append(str(ip.data))
                                self.textBrowser.append('')
                        elif dstaddr != '' and srcaddr == '':
                            if ip.dst_address == dstaddr:
                                self.textBrowser.append(
                                    '协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                                self.textBrowser.append(str(ip.data))
                                self.textBrowser.append('')
                        else:
                            if ip.dst_address == dstaddr and ip.src_address == srcaddr:
                                self.textBrowser.append(
                                    '协议: %s %s -> %s' % (ip.protocol, ip.src_address, ip.dst_address))
                                self.textBrowser.append(str(ip.data))
                                self.textBrowser.append('')
                i += 1


        except KeyboardInterrupt:
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sys.exit()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = QMainWindow()
    form = Box(mainWindow)
    mainWindow.show()
    sys.exit(app.exec_())
