"""
这是等待你完成的代码。正常情况下，本文件是你唯一需要改动的文件。
你可以任意地改动此文件，改动的范围当然不限于已有的五个函数里。（只要已有函数的签名别改，要是签名改了main里面就调用不到了）
在开始写代码之前，请先仔细阅读此文件和api文件。这个文件里的五个函数是等你去完成的，而api里的函数是供你调用的。
提示：TCP是有状态的协议，因此你大概率，会需要一个什么样的数据结构来记录和维护所有连接的状态
"""
from api import *
from scapy.all import *
from collections import deque
import time


def identifier2tuple(identifier: ConnectionIdentifier):
    """
    将ConnectionIdentifier转换为四元组，以便作为字典的键。
    @param identifier: ConnectionIdentifier
    @return (src_ip, src_port, dst_ip, dst_port)
    注：此函数是在实验文档的提示下完成的。
    """
    return (identifier['src']['ip'], identifier['src']['port'], identifier['dst']['ip'], identifier['dst']['port'])


def parse_TCP_header(data: bytes):
    """
    将TCP报文头部进行解析，返回序号、确认号、标志位、纯数据。
    @param data: bytes
    @return (seq, ack, flags, pure_data)
    注：此部分是在copilot插件的帮助下完成的（https://github.com/features/copilot）。
    """
    seq = int.from_bytes(data[4:8], byteorder='big')
    ack = int.from_bytes(data[8:12], byteorder='big')
    if data[13] & 0x01:
        flags = 'FA'
    elif (data[13] >> 1) & 0x01:
        flags = 'SA'
    elif (data[13] >> 2) & 0x01:
        flags = 'RA'
    else:
        flags = 'otherACK'
    header_len = (data[12] >> 4) * 4
    pure_data = data[header_len:]
    return seq, ack, flags, pure_data


class Connection:
    """
    连接类，此部分与助教原本给出的代码有差别，采用类可以实现多个连接的并发。
    注：在提出整个类的设计时，与于骏浩同学（2020012847）、孙一川同学（2020012860）讨论过，共同review过代码。
        类中的函数都或多或少在copilot的帮助下实现bug-free，tcp_rx函数与于骏浩和孙一川同学进行了重点讨论，在tcp_rx函数的注释中也有提到。
        此外，本部分中所有的报文（后缀为_packet）都是通过scapy库构造的，copilot（https://github.com/features/copilot）进行了帮助填充参数的工作。
    """
    def __init__(self, conn: ConnectionIdentifier) -> None:
        """
        初始化一系列变量。
        @param conn: ConnectionIdentifier
        """
        self.send_buffer = deque(maxlen=100) # 发送缓冲区 [pure_data, seq, len, flags]
        self.time_stamp = 0                  # 记录时间戳
        self.conn = conn                     # 连接对象
        self.state = 'CLOSED'                # 连接状态
        self.next_send = 0                   # 下一个发送的可用序号
        self.send_base = 0                   # 发送窗口的起始序号
        self.next_recv = 0                   # 下一个接收的可用序号
        self.src_ip = conn['src']['ip']      # 源ip
        self.dst_ip = conn['dst']['ip']      # 目的ip
        self.src_port = conn['src']['port']  # 源端口
        self.dst_port = conn['dst']['port']  # 目的端口

    def app_connect(self):
        """
        当有应用想要发起一个新的连接时，会调用此函数。想要连接的对象在conn里提供了。
        你应该向想要连接的对象发送SYN报文，执行三次握手的逻辑。
        当连接建立好后，你需要调用app_connected函数，通知应用层连接已经被建立好了。
        """
        SYN_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='S', seq=0)
        SYN = bytes(SYN_packet[TCP])
        self.send_buffer.append([b'', 0, 1, 'S'])                    # SYN报文也要放入buffer，以备重传的需要
        self.time_stamp = time.time()                                # 开启定时器
        tcp_tx(self.conn, SYN)
        self.state = 'SYN_SENT'
        self.next_send += 1


    def app_send(self, data: bytes):
        """
        当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
        @param data: bytes（数据内容，是字节数组。）
        """
        DATA_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.next_recv) / data
        DATA = bytes(DATA_packet[TCP])
        if self.send_buffer.__len__() == 0:
            self.time_stamp = time.time()                             # 如果发送缓冲区为空，说明现在发的这个是send_base，开启定时器
        self.send_buffer.append([data, self.next_send, len(data), 'A'])
        tcp_tx(self.conn, DATA)
        self.next_send += len(data)


    def app_fin(self):
        """
        当应用层想要半关闭连接(FIN)时，会调用此函数。
        """
        FIN_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='FA', seq=self.next_send, ack=self.next_recv)
        FIN = bytes(FIN_packet[TCP])
        self.send_buffer.append([b'', self.next_send, 1, 'FA'])       # FIN报文也要放入buffer，以备重传的需要
        tcp_tx(self.conn, FIN)
        self.state = 'FIN_WAIT_1'
        self.next_send += 1


    def app_rst(self):
        """
        当应用层想要重置连接(RES)时，会调用此函数。
        """
        RST_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='RA', seq=self.next_send, ack=self.next_recv)
        RST = bytes(RST_packet[TCP])
        tcp_tx(self.conn, RST)
        self.state = 'CLOSED'


    def tcp_rx(self, data: bytes):
        """
        当收到TCP报文时，会调用此函数。
        正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数。
        :param data: bytes（TCP报文内容，是字节数组，含TCP报头，不含IP报头。）
        注：此部分代码在copilot（https://github.com/features/copilot）的帮助下完成，其中的状态转移由于内容较为复杂，
            与于骏浩（2020012847）、孙一川（2020012860）同学进行了重点讨论，共同进行过代码review的工作。
        """
        data_seq, data_ack, data_flags, pure_data = parse_TCP_header(data)
        if data_flags == 'RA':                                       # 如果收到RST报文，通知应用层，直接关闭连接
            if data_seq == self.next_recv:
                self.state = 'CLOSED'
                app_peer_rst(self.conn)
                return
            else:
                return
        
        else:
            if self.state == 'SYN_SENT' and data_flags == 'SA':      # 如果是SYN_SENT状态且收到SYN+ACK，回复ACK
                if data_ack == self.next_send:                       # 如果收到的SYN+ACK正确
                    ACK_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=data_ack, ack=data_seq+1)
                    ACK = bytes(ACK_packet[TCP])
                    tcp_tx(self.conn, ACK)
                    self.state = 'ESTABLISHED'
                    self.next_recv = data_seq + 1
                    app_connected(self.conn)
                    self.send_buffer.popleft()                       # 发送缓冲区中的SYN报文已经被确认，可以删除
                    self.time_stamp = time.time()                    # 开启定时器
                    return
                else:
                    return
            
            else:
                # 此部分的逻辑尤为重要，这里的思想是这样的：我们将ACK导致的窗口变化和数据导致的窗口变化分开处理，并且在最后进行状态转移的判断。
                # 处理ACK的部分在第一个if语句中，处理数据的部分在第二个if语句中，最后进行状态转移的判断在第三个if语句中。
                if data_ack >= self.send_base and data_ack <= self.next_send:                                # part1：如果收到的ACK正确，更新窗口send_base
                    self.send_base = data_ack
                    while self.send_buffer.__len__() != 0 and self.send_buffer[0][1] < self.send_base:       # part1：如果发送缓冲区中的报文已经被确认，可以删除
                        self.send_buffer.popleft()
                        self.time_stamp = time.time()
                else:
                    pass
                
                if len(pure_data) == 0:                                                                      # part2：如果收到的是ACK报文，直接返回
                    pass
                else:                                                                                        # part2：如果收到的是数据报文，上交给应用层，并更新next_recv
                    if data_seq == self.next_recv:                                                           # 如果收到的seq正确，上交给应用层
                        self.next_recv += len(pure_data)
                        ACK_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.next_recv)
                        ACK = bytes(ACK_packet[TCP])
                        tcp_tx(self.conn, ACK)
                        app_recv(self.conn, pure_data)
                        return
                    else:
                        ACK_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.next_recv)
                        ACK = bytes(ACK_packet[TCP])
                        tcp_tx(self.conn, ACK)
                        return
                
                if data_flags == 'FA':                                                                       # part3：如果收到FIN报文，进行状态转移的讨论
                    if data_seq == self.next_recv:                                                           # 如果收到的seq正确，回复ACK，无论处在哪个状态
                        ACK_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.next_recv+1)
                        ACK = bytes(ACK_packet[TCP])
                        tcp_tx(self.conn, ACK)
                        self.next_recv += 1
                    else:
                        ACK_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.next_recv)
                        ACK = bytes(ACK_packet[TCP])
                        tcp_tx(self.conn, ACK)
                        return
                    
                    if self.state == 'ESTABLISHED':                                                          # 如果是ESTABLISHED状态，回复ACK，进入CLOSE_WAIT状态
                        self.state = 'CLOSE_WAIT'
                        app_peer_fin(self.conn)
                        return

                    elif self.state == 'FIN_WAIT_1':                                                         # 如果是FIN_WAIT_1状态，回复ACK，进入CLOSING状态
                        self.state = 'CLOSING'
                        return

                    elif self.state == 'FIN_WAIT_2':                                                         # 如果是FIN_WAIT_2状态，回复ACK，进入TIME_WAIT状态
                        self.state = 'TIME_WAIT'
                        # 本来应该是等一会再关闭，这里就不等了
                        release_connection(self.conn)
                        return
                    
                    else:
                        return
                        
                    
                else:                                                                                        # part3：如果收到的是普通的ACK报文，进行状态转移的讨论
                    if data_seq == self.next_recv:                                                        
                        if self.state == 'FIN_WAIT_1':                                                           # 如果是FIN_WAIT_1状态，检查队列是否空
                            if self.send_buffer.__len__() == 0:
                                self.state = 'FIN_WAIT_2'
                                return
                        
                        elif self.state == 'LAST_ACK':                                                           # 如果是LAST_ACK状态，直接关闭
                            self.state = 'CLOSED'
                            release_connection(self.conn)
                            return
                    
                    else:
                        return
                        
                            
    def tick(self):
        """
        这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中。
        """
        if time.time() - self.time_stamp > 3:
            if len(self.send_buffer) != 0:                                                                   # 如果队列不为空，重传队首报文  
                send_base_data, send_base_seq, send_base_len, send_base_flags = self.send_buffer[0]
                resend_data_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags=send_base_flags, seq=send_base_seq, ack=self.next_recv) / send_base_data
                resend_data = bytes(resend_data_packet[TCP])
                tcp_tx(self.conn, resend_data)
                self.time_stamp = time.time()                                                                # 重传后更新时间戳
            else:
                pass
        else:
            pass


# --------------------------------- 以下是主函数部分的接口 ---------------------------------


connection_list = {}


def app_connect(conn: ConnectionIdentifier):
    """
    当有应用想要发起一个新的连接时，会调用此函数。想要连接的对象在conn里提供了。
    你应该向想要连接的对象发送SYN报文，执行三次握手的逻辑。
    当连接建立好后，你需要调用app_connected函数，通知应用层连接已经被建立好了。
    @param conn: ConnectionIdentifier（连接对象，里面包含了想要连接的对象的地址和端口）
    注：对于connection_list中每一个连接的存储形式与于骏浩（2020012847）同学进行了讨论，存在互相参考。在下面的函数中也是类似的，不再一一注明。
    """
    connection = Connection(conn)
    connection_list[identifier2tuple(conn)] = connection
    connection.app_connect()
    print("app_connect", conn)


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    @param conn: ConnectionIdentifier（连接对象，里面包含了想要连接的对象的地址和端口）
    @param data: bytes（想要发送的数据）
    """
    connection = connection_list[identifier2tuple(conn)]
    connection.app_send(data)
    print("app_send", conn, data.decode(errors='replace'))


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    @param conn: ConnectionIdentifier（连接对象，里面包含了想要连接的对象的地址和端口）
    """
    connection = connection_list[identifier2tuple(conn)]
    connection.app_fin()
    print("app_fin", conn)


def app_rst(conn: ConnectionIdentifier):
    """
    当应用层想要重置连接(RES)时，会调用此函数
    @param conn: ConnectionIdentifier（连接对象，里面包含了想要连接的对象的地址和端口）
    """
    connection = connection_list[identifier2tuple(conn)]
    connection.app_rst()
    print("app_rst", conn)


def tcp_rx(conn: ConnectionIdentifier, data: bytes):
    """
    当收到TCP报文时，会调用此函数。
    正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数
    @param conn: ConnectionIdentifier（连接对象，里面包含了想要连接的对象的地址和端口）
    @param data: bytes（TCP报文内容，是字节数组，含TCP报头，不含IP报头）
    """
    connection = connection_list[identifier2tuple(conn)]
    connection.tcp_rx(data)
    print("tcp_rx", conn, data.decode(errors='replace'))


def tick():
    """
    这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中，而不是一直阻塞在main文件里面。
    当main文件调用这一函数时，这一函数会分别调用当前所有连接的tick函数。
    """
    for connection in connection_list.values():
        connection.tick()
    pass