#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <stdint.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#define ETHERNET_SIZE 14

// Ethernet header
struct ethhdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

// IPv4 header (不含 options)
struct iphdr {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// IGMPv3 Report 固定頭
struct igmpv3_report {
    uint8_t  type;      // 0x22
    uint8_t  reserved1;
    uint16_t checksum;
    uint16_t reserved2;
    uint16_t num_group_records;
};

// IGMPv3 Group Record
struct igmpv3_group_record {
    uint8_t  record_type;
    uint8_t  aux_data_len;
    uint16_t num_sources;
    uint32_t multicast_addr;
    uint32_t source_addr[1]; // 可以擴充
};

// 計算 checksum
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    while (nwords-- > 0)
        sum += *buf++;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    pcap_t *fp;

    // 取得裝置列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    // 選第一張網卡
    dev = alldevs;
    if (!dev) {
        printf("No device found\n");
        return 1;
    }
    printf("Using device: %s\n", dev->name);

    // 開啟
    if ((fp = pcap_open_live(dev->name, 65536, 1, 1, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open the adapter. %s\n", errbuf);
        return 1;
    }

    // 封包 buffer
    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    // Ethernet header
    struct ethhdr *eth = (struct ethhdr *)packet;
    uint8_t dst_mac[6] = {0x01,0x00,0x5e,0x01,0x01,0x01}; // Multicast MAC for 239.1.1.1
    memcpy(eth->dst, dst_mac, 6);
    uint8_t src_mac[6] = {0x00, 0xe0, 0x4c, 0x68, 0x03, 0x53}; // 換成你自己網卡的 MAC
    memcpy(eth->src, src_mac, 6);
    eth->ethertype = htons(0x0800); // IPv4

    // IP header
    struct iphdr *ip = (struct iphdr *)(packet + ETHERNET_SIZE);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0xc0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct igmpv3_report) + sizeof(struct igmpv3_group_record));
    ip->id = htons(1);
    ip->frag_off = 0;
    ip->ttl = 1;
    ip->protocol = 2; // IGMP
    ip->saddr = inet_addr("10.35.70.34"); // 換成你的 host IP
    ip->daddr = inet_addr("224.0.0.22");    // IGMPv3 Multicast
    ip->check = 0;
    ip->check = checksum((unsigned short *)ip, ip->ihl*2);

    // IGMPv3 Report
    struct igmpv3_report *igmp = (struct igmpv3_report *)(packet + ETHERNET_SIZE + sizeof(struct iphdr));
    igmp->type = 0x22;
    igmp->reserved1 = 0;
    igmp->checksum = 0;
    igmp->reserved2 = 0;
    igmp->num_group_records = htons(1);

    struct igmpv3_group_record *record = (struct igmpv3_group_record *)(igmp + 1);
    record->record_type = 1; // MODE_IS_INCLUDE
    record->aux_data_len = 0;
    record->num_sources = htons(1);
    record->multicast_addr = inet_addr("239.1.1.1");
    record->source_addr[0] = inet_addr("192.168.1.200"); // 要接收的 source

    // 計算 IGMP checksum (從 IGMPv3 header 開始算)
    int igmp_len = sizeof(struct igmpv3_report) + sizeof(struct igmpv3_group_record);
    igmp->checksum = checksum((unsigned short *)igmp, igmp_len/2);

    // 送出
    if (pcap_sendpacket(fp, packet, ETHERNET_SIZE + ntohs(ip->tot_len)) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(fp));
    } else {
        printf("IGMPv3 report sent!\n");
    }

    pcap_close(fp);
    pcap_freealldevs(alldevs);
    return 0;
}
