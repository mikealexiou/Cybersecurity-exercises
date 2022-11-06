import socket
import struct
import textwrap
import time

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connection.recvfrom(65535)
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(raw_data)
        dest_mac, src_mac, eth_proto, eth_data = ethernet_frame(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto_ipv4, src, target, data_ip = ipv4_packet(eth_data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto_ipv4, src, target))

            # ICMP
            if proto_ipv4 == 1:
                icmp_type, code, checksum, icmp_data = icmp(data_ip)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp_data))

            # TCP
            elif proto_ipv4 == 6:
                src_port,dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = tcp(data_ip)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))

                if len(tcp_data) > 0:

                    # HTTP
                    if src_port == 80 or dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http_data = http(tcp_data)
                            http_info = str(http_data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp_data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp_data))

            # UDP
            elif proto_ipv4 == 17:
                udp_src_port, udp_dest_port, size, udp_data = udp(data_ip)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_src_port, udp_dest_port, size))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, data_ip))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth_data))



#def get_mac_addr(mac_raw):



#def format_multi_line(prefix, string, size=80):



#def ethernet_frame(data):



def http(data):
    try:
        return data.decode('utf-8')
    except:
        return data


#def icmp(data):



#def ipv4_packet(data):



def ipv4(addr):
    return '.'.join(map(str, addr))


#def tcp(data):



#def udp(data):



main()