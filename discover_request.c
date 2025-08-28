#include <pcap.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "packet.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

int main() {
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

    uint32_t req_ip = inet_addr("10.35.72.7");
    uint32_t lease_time = 172800; // 2天

    // 發送 Discover
    int pkt_len = build_dhcp_packet(packet, src_mac, 1, req_ip, 0 ,lease_time);
    if (pcap_sendpacket(fp, packet, pkt_len) != 0) {
        printf("Error sending DHCP Discover\n");
    } else {
        printf("Sent DHCP Discover\n");
    }

    //確認是否是discover和request之間間隔過常導致server沒發送ack
    // Sleep(3000);

    struct bpf_program fcode;
    if (pcap_compile(fp, &fcode, "udp and (port 67 or port 68)", 1, 0xffffffff) < 0) {
        printf("Unable to compile the packet filter.\n");
        pcap_close(fp);
        return -1;
    }
    if (pcap_setfilter(fp, &fcode) < 0) {
        printf("Error setting the filter.\n");
        pcap_close(fp);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(fp, &header, &pkt_data);
        if (res == 1) {
            printf("receive packet\n");
            // TODO: 在這裡解析 DHCP Offer
            // 先取 IP header
            struct iphdr *ip = (struct iphdr *)(pkt_data + ETHERNET_SIZE);
            int ip_header_len = ip->ihl * 4;
            // 取 UDP header
            struct udphdr *udp = (struct udphdr *)(pkt_data + ETHERNET_SIZE + ip_header_len);
            // 
            int udp_payload_len = ntohs(udp->len) - sizeof(struct udphdr);

            // DHCP 固定長度 = 236 bytes + 4 bytes magic cookie = 240
            int dhcp_fixed_len = 240;
            if (udp_payload_len <= dhcp_fixed_len) {
                printf("錯誤: DHCP payload 太短 (len=%d)\n", udp_payload_len);
                continue;
            }
            
            struct dhcp_packet *dhcp = (struct dhcp_packet *)((uint8_t *)udp + sizeof(struct udphdr));
            uint8_t *options = dhcp->options+4;//magic code

            int options_len = udp_payload_len - dhcp_fixed_len;
            printf("options_len:%d\n",options_len);
            uint8_t *messageType = dhcp_get_option(options,53,options_len);
            if (2 == (int) messageType[0]) {
                uint8_t *ip = (uint8_t *)&dhcp->yiaddr;
                printf("yiaddr = %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
                memcpy(&req_ip,&dhcp->yiaddr,4);
                break;
            }
        }
    }

    
    uint32_t server_ip = inet_addr("10.35.72.1");

    // 發送 Request
    pkt_len = build_dhcp_packet(packet, src_mac, 3, req_ip, server_ip,0);
    if (pcap_sendpacket(fp, packet, pkt_len) != 0) {
        printf("Error sending DHCP Request\n");
    } else {
        printf("Sent DHCP Request\n");
    }

    pcap_close(fp);
    pcap_freealldevs(alldevs);
    return 0;
}
