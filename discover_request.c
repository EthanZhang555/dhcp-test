#include <pcap.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#define ETHERNET_SIZE 14
#define IP_SIZE 20
#define UDP_SIZE 8

// ---------------- Ethernet, IP, UDP ----------------
struct ethhdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct iphdr {
    uint8_t ihl:4, version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

// ---------------- DHCP ----------------
struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
};

// ---------------- Pseudo Header for UDP checksum ----------------
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_length;
};

// ---------------- Checksum functions ----------------
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    while (nwords-- > 0) sum += *buf++;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short udp_checksum(const void *buff, unsigned short len, struct pseudo_header *pshdr) {
    unsigned long sum = 0;
    const unsigned short *ptr;

    // add pseudo header
    ptr = (unsigned short *)pshdr;
    for (int i = 0; i < sizeof(struct pseudo_header) / 2; i++)
        sum += *ptr++;

    // add UDP header + data
    ptr = (unsigned short *)buff;
    for (int i = 0; i < (len / 2); i++)
        sum += *ptr++;

    if (len & 1) // odd length, pad last byte
        sum += *((uint8_t *)ptr);

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}

// ---------------- Build DHCP Discover / Request ----------------
int build_dhcp_packet(uint8_t *packet, const uint8_t *src_mac, int is_request, uint32_t req_ip, uint32_t server_ip) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + ETHERNET_SIZE);
    struct udphdr *udp = (struct udphdr *)(packet + ETHERNET_SIZE + IP_SIZE);
    struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet + ETHERNET_SIZE + IP_SIZE + UDP_SIZE);

    memset(packet, 0, 1500);

    // Ethernet
    memset(eth->dst, 0xff, 6); // broadcast
    memcpy(eth->src, src_mac, 6);
    eth->type = htons(0x0800); // IPv4

    // IP
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 128;
    ip->protocol = 17; // UDP
    ip->saddr = 0;     // 0.0.0.0
    ip->daddr = 0xffffffff; // 255.255.255.255

    // UDP
    udp->source = htons(68);
    udp->dest = htons(67);

    // DHCP
    dhcp->op = 1; // BOOTREQUEST
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = htonl(0x3903F326); // 隨便一個 transaction id
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000); // broadcast flag
    memcpy(dhcp->chaddr, src_mac, 6);

    // DHCP magic cookie
    dhcp->options[0] = 99;
    dhcp->options[1] = 130;
    dhcp->options[2] = 83;
    dhcp->options[3] = 99;

    int idx = 4;

    // Message type
    dhcp->options[idx++] = 53;
    dhcp->options[idx++] = 1;
    dhcp->options[idx++] = (is_request ? 3 : 1); // 1 = Discover, 3 = Request

    if (is_request) {
        // Requested IP
        dhcp->options[idx++] = 50;
        dhcp->options[idx++] = 4;
        memcpy(&dhcp->options[idx], &req_ip, 4);
        idx += 4;

        // DHCP Server Identifier
        dhcp->options[idx++] = 54;
        dhcp->options[idx++] = 4;
        memcpy(&dhcp->options[idx], &server_ip, 4);
        idx += 4;
    }

    // Client Identifier
    dhcp->options[idx++] = 61;
    dhcp->options[idx++] = 7;
    dhcp->options[idx++] = 1; // Ethernet
    memcpy(&dhcp->options[idx], src_mac, 6);
    idx += 6;

    // End option
    dhcp->options[idx++] = 255;

    int dhcp_len = sizeof(struct dhcp_packet) - sizeof(dhcp->options) + idx;

    udp->len = htons(UDP_SIZE + dhcp_len);
    ip->tot_len = htons(IP_SIZE + UDP_SIZE + dhcp_len);

    // IP checksum
    ip->check = 0;
    ip->check = checksum((unsigned short *)ip, ip->ihl * 2);

    // UDP checksum
    struct pseudo_header psh;
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = udp->len;

    udp->check = 0;
    udp->check = udp_checksum((unsigned short *)udp, ntohs(udp->len), &psh);

    return ETHERNET_SIZE + IP_SIZE + UDP_SIZE + dhcp_len;
}

// ---------------- Main ----------------
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

    // 隨便給個 MAC
    uint8_t src_mac[6] = {0x00, 0xe0, 0x4c, 0x68, 0x03, 0x53};
    uint8_t packet[1500];

    // 發送 Discover
    int pkt_len = build_dhcp_packet(packet, src_mac, 0, 0, 0);
    if (pcap_sendpacket(fp, packet, pkt_len) != 0) {
        printf("Error sending DHCP Discover\n");
    } else {
        printf("Sent DHCP Discover\n");
    }

    // TODO: 這裡應該接收 Offer，再解析 yiaddr / server id
    // 我們先假設
    uint32_t req_ip = inet_addr("10.35.72.3");
    uint32_t server_ip = inet_addr("10.35.72.1");

    // 發送 Request
    pkt_len = build_dhcp_packet(packet, src_mac, 1, req_ip, server_ip);
    if (pcap_sendpacket(fp, packet, pkt_len) != 0) {
        printf("Error sending DHCP Request\n");
    } else {
        printf("Sent DHCP Request\n");
    }

    pcap_close(fp);
    pcap_freealldevs(alldevs);
    return 0;
}
