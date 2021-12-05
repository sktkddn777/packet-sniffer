# 컴퓨터 네트워크 설계 

import os
import pandas as pd
import matplotlib.pyplot as plt

from scapy.all import AsyncSniffer, wrpcap
from scapy.plist import PacketList
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP


def print_sniffer(pkt: Ether):
    print(pkt.summary())


def sniff_routine() -> PacketList:
    sniffer = AsyncSniffer(prn=lambda x: x.summary(), filter='ip')

    print("패킷 캡처 시작: 1")
    print("패킷 캡처 종료: 2")
    while True:
        start = input()
        if start == "1":
            break

    sniffer.start()

    while True:
        stop = input()
        if stop == "2":
            break

    sniff_result = sniffer.stop()
    # sniff_result에 저장되어 있는 패킷을 output.cap에 저장.
    wrpcap("output/output.cap", sniff_result)
    return sniff_result


def analyzer(packet_list: PacketList):
    """
    https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    이 링크에서 csv로 service name이랑 port num을 받아온다.
    """
    known_ports = pd.read_csv("service-names-port-numbers.csv")

    output = open('output/output.txt', 'w')
    output.write(str(packet_list) + "\n")
    output.write("\n----------------------------------------------------\n\n")

    # 데이터 분석을 위해 각각의 dictionary를 만들어둔다.
    src_count = dict()
    dst_count = dict()
    sport_count = dict()
    dport_count = dict()
    proto_count = dict()
    frag_count = 0
    min_size = packet_list[0][IP].len
    max_size = packet_list[0][IP].len
    total_size = 0

    for pkt in packet_list:
        # src
        src = pkt[IP].src
        src_count[src] = src_count.get(src, 0) + 1

        # dst
        dst = pkt[IP].dst
        dst_count[dst] = dst_count.get(dst, 0) + 1

        # protocol
        protocol = pkt.sprintf("%IP.proto%")
        proto_count[protocol] = proto_count.get(protocol, 0) + 1

        # send_port
        sport = pkt.sport
        sport_names = (known_ports.loc[
            (known_ports["Port Number"] == str(sport)) & (known_ports["Transport Protocol"] == protocol)])[
            "Service Name"].to_numpy()
        if len(sport_names) != 0 and sport_names[0] != "":
            sport = str(sport_names[0])
            sport += "(" + str(pkt.sport) + ")"
        sport_count[sport] = sport_count.get(sport, 0) + 1

        # des_port  
        dport = pkt.dport
        dport_names = (known_ports.loc[
            (known_ports["Port Number"] == str(dport)) & (known_ports["Transport Protocol"] == protocol)])[
            "Service Name"].to_numpy()
        if len(dport_names) != 0 and dport_names[0] != "":
            dport = str(dport_names[0])
            dport += "(" + str(pkt.dport) + ")"
        dport_count[dport] = dport_count.get(dport, 0) + 1

        # https://en.wikipedia.org/wiki/IPv4#Header 헤더 내용 있음.
        if "MF" in pkt[IP].flags or pkt[IP].frag != 0:
            frag_count += 1

        total_size += pkt[IP].len
        min_size = min(min_size, pkt[IP].len)
        max_size = max(max_size, pkt[IP].len)


    # pandas dataframe 이용한 데이터 분석
    # src, dst, send_port, des_port, proto_count
    # output.txt에 분석 내용 쓰기.
    src_count = pd.DataFrame(sorted(src_count.items(), key=lambda item: item[1], reverse=True))
    src_count.columns = ["Sender(source) IP", "Datagram count"]
    src_count.loc[src_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                          shadow=False,
                                                          labels=src_count["Sender(source) IP"], legend=False,
                                                          title="Sender(source) IP")
    output.write(src_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    dst_count = pd.DataFrame(sorted(dst_count.items(), key=lambda item: item[1], reverse=True))
    dst_count.columns = ["Receiver(destination) IP", "Datagram count"]
    dst_count.loc[dst_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                          shadow=False,
                                                          labels=dst_count["Receiver(destination) IP"], legend=False,
                                                          title="Receiver(destination) IP")
    output.write(dst_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    sport_count = pd.DataFrame(sorted(sport_count.items(), key=lambda item: item[1], reverse=True))
    sport_count.columns = ["Sender(source) Port", "Datagram count"]
    sport_count.loc[sport_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                              shadow=False,
                                                              labels=sport_count["Sender(source) Port"], legend=False,
                                                              title="Sender(source) Port")
    output.write(sport_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    dport_count = pd.DataFrame(sorted(dport_count.items(), key=lambda item: item[1], reverse=True))
    dport_count.columns = ["Receiver(destination) Port", "Datagram count"]
    dport_count.loc[dport_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                              shadow=False,
                                                              labels=dport_count["Receiver(destination) Port"],
                                                              legend=False,
                                                              title="Receiver(destination) Port")
    output.write(dport_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    proto_count = pd.DataFrame(sorted(proto_count.items(), key=lambda item: item[1], reverse=True))
    proto_count.columns = ["Transport Layer Protocol", "Datagram count"]
    proto_count.plot(kind="pie", y="Datagram count", startangle=90,
                     shadow=False,
                     labels=proto_count["Transport Layer Protocol"],
                     legend=False,
                     title="Transport Layer Protocol")
    output.write(proto_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    output.write("Fragmented datagram count: " + str(frag_count) + "\n")
    output.write("\n----------------------------------------------------\n\n")

    average_size = total_size // len(packet_list)
    output.write("Smallest captured datagram size: " + str(min_size) + "\n")
    output.write("Largest captured datagram size: " + str(max_size) + "\n")
    output.write("Average captured datagram size: " + str(average_size) + "\n")
    output.write("\n----------------------------------------------------\n\n")

    output.close()
    plt.show()
    return None


def main():
    '''
    main 함수
    output 폴더를 만들고 
    '''
    if not os.path.exists('output'):
        os.makedirs('output')
    sniff_result = sniff_routine()
    analyzer(sniff_result)
    print(sniff_result)


if __name__ == "__main__":
    main()
