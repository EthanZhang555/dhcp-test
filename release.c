#include <pcap.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "packet.h"

int main(){
    pcap_if_t *alldevs, *d;
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 找到第一個裝置
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    d = alldevs; // 選第一張卡
    if (!d) {
        printf("No interfaces found.\n");
        return -1;
    }
    printf("Using device: %s\n", d->name);

    // 打開裝置
    if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        printf("Unable to open adapter: %s\n", errbuf);
        return -1;
    }

    uint8_t src_mac[6] = {0x00, 0xe0, 0x4c, 0x68, 0x03, 0x53};
    uint8_t packet[1500];

    uint32_t req_ip = inet_addr("10.35.72.2");
    uint32_t lease_time = 0;
    uint32_t server_ip = inet_addr("10.35.72.1");

    // 發送 release
    int pkt_len = build_dhcp_packet(packet, src_mac, 7, req_ip, server_ip ,lease_time);
    if (pcap_sendpacket(fp, packet, pkt_len) != 0) {
        printf("Error sending DHCP Release\n");
    } else {
        printf("Sent DHCP Release\n");
    }
}