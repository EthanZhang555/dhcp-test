#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include <Packet32.h>
#include <Ntddndis.h>
#include <stdbool.h>

#define ETHERNET_SIZE 14
#define IP_SIZE       20
#define UDP_SIZE      8

// Ethernet header
struct eth_header {
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short type;
};

// IP header (without options)
struct ip_header {
    unsigned char  ver_ihl;       // 版本(4位元)+IHL(4位元)
    unsigned char  tos;
    unsigned short tlen;
    unsigned short identification;
    unsigned short flags_fo;
    unsigned char  ttl;
    unsigned char  proto;
    unsigned short crc;
    unsigned int   saddr;
    unsigned int   daddr;
};

// UDP header
struct udp_header {
    unsigned short sport;
    unsigned short dport;
    unsigned short len;
    unsigned short crc;
};

// DHCP packet structure
struct dhcp_packet {
    unsigned char op;       // Message op code
    unsigned char htype;    // Hardware type
    unsigned char hlen;     // Hardware address length
    unsigned char hops;
    unsigned int  xid;      // Transaction ID
    unsigned short secs;
    unsigned short flags;
    unsigned int  ciaddr;
    unsigned int  yiaddr;
    unsigned int  siaddr;
    unsigned int  giaddr;
    unsigned char chaddr[16]; // Client MAC
    unsigned char sname[64];
    unsigned char file[128];
    unsigned char options[312]; // DHCP options
};

// Checksum function for IP header
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// 取得選定裝置的 MAC 地址
int get_mac_address(pcap_if_t *dev, unsigned char mac[6]) {
    LPADAPTER lpAdapter;
    PPACKET_OID_DATA OidData;
    BOOLEAN status;
    int success = 0;

    lpAdapter = PacketOpenAdapter(dev->name);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        return 0;
    }

    OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (!OidData) {
        PacketCloseAdapter(lpAdapter);
        return 0;
    }

    OidData->Oid = OID_802_3_CURRENT_ADDRESS;
    OidData->Length = 6;

    status = PacketRequest(lpAdapter, FALSE, OidData);
    if (status) {
        memcpy(mac, OidData->Data, 6);
        success = 1;
    }

    free(OidData);
    PacketCloseAdapter(lpAdapter);

    return success;
}

uint8_t *dhcp_get_option(uint8_t *options, int code) {
    uint8_t *opt = options;
    int index =0;
    while (*opt != 255) {
        if (*opt == 0) { opt++; continue; } // Pad
        uint8_t opt_code = opt[0];
        uint8_t len = opt[1];
        if (opt_code == code) {
            return &opt[2]; // 回傳 data 開頭
        }
        // printf("opt_code:%d, len:%d\n",opt_code,len);
        opt += 2 + len;
        index += 2 + len;
    }
    printf("index:%d\n",index);
    return NULL; // not found
}


int main() {
    pcap_if_t *alldevs, *d;
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char packet[1024];
    int pkt_len;

    // 取得介面
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    int i=0, choice;
    // 列出所有介面
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("No interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    // 讓使用者選擇
    printf("Enter the interface number (1-%d): ", i);
    scanf("%d", &choice);

    if (choice < 1 || choice > i) {
        printf("Invalid choice.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 找到選到的介面
    d = alldevs;
    for (i = 1; i < choice; i++) {
        d = d->next;
    }

    printf("You selected: %s\n", d->name);

    // 開啟介面
    if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        printf("Error opening adapter: %s\n", errbuf);
        return -1;
    }

    // 組封包 (Ethernet + IP + UDP + DHCP)
    struct eth_header *eth = (struct eth_header *)packet;
    struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct eth_header));
    struct udp_header *udp = (struct udp_header *)((unsigned char *)ip + sizeof(struct ip_header));
    struct dhcp_packet *dhcp = (struct dhcp_packet *)((unsigned char *)udp + sizeof(struct udp_header));
    
    unsigned char my_mac[6];
    if (get_mac_address(d, my_mac)) {
        printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
            my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

        memcpy(eth->src, my_mac, 6);       // Ethernet來源MAC
    } else {
        printf("Failed to get MAC address.\n");
        return -1;
    }


    // Ethernet
    memset(eth->dst, 0xff, 6); // broadcast
    eth->type = htons(0x0800);

    // IP header
    ip->ver_ihl = 0x45;
    ip->tos = 0;
    ip->tlen = htons(sizeof(struct ip_header) + sizeof(struct udp_header) + sizeof(struct dhcp_packet));
    ip->identification = htons(0x1234);
    ip->flags_fo = 0;
    ip->ttl = 64;
    ip->proto = 17; // UDP
    ip->crc = 0;
    ip->saddr = 0; // 0.0.0.0
    ip->daddr = 0xffffffff; // 255.255.255.255
    ip->crc = checksum((unsigned short *)ip, sizeof(struct ip_header)/2);

    // UDP
    udp->sport = htons(68);
    udp->dport = htons(67);
    udp->len = htons(sizeof(struct udp_header) + sizeof(struct dhcp_packet));
    udp->crc = 0;

    // DHCP
    memset(dhcp, 0, sizeof(struct dhcp_packet));
    dhcp->op = 1; // Boot Request
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->xid = htonl(rand()); // Transaction ID
    memcpy(dhcp->chaddr, eth->src, 6);

    int opt_idx = 0;

    // DHCP magic cookie
    dhcp->options[opt_idx++] = 99;
    dhcp->options[opt_idx++] = 130;
    dhcp->options[opt_idx++] = 83;
    dhcp->options[opt_idx++] = 99;

    // DHCP options: Message type = Discover
    dhcp->options[opt_idx++] = 53;
    dhcp->options[opt_idx++] = 1;
    dhcp->options[opt_idx++] = 1; // DHCP Discover

    // Requested IP Address = 10.35.72.5
    dhcp->options[opt_idx++] = 50;  // Option code
    dhcp->options[opt_idx++] = 4;   // Length
    dhcp->options[opt_idx++] = 10;
    dhcp->options[opt_idx++] = 35;
    dhcp->options[opt_idx++] = 72;  
    dhcp->options[opt_idx++] = 5; 

    // End option
    dhcp->options[opt_idx++] = 255;

    pkt_len = sizeof(struct eth_header) + sizeof(struct ip_header) + sizeof(struct udp_header) + sizeof(struct dhcp_packet);

    // 發送封包
    if (pcap_sendpacket(fp, packet, pkt_len) != 0) {
        printf("Error sending the packet: %s\n", pcap_geterr(fp));
        return -1;
    }

    printf("DHCP Discover sent!\n");

    // 設定 BPF 過濾器 (只要 DHCP 封包)
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

    printf("Listening for DHCP packets...\n");
    // 進入接收 loop
    while (1) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(fp, &header, &pkt_data);
        bool is_dhcp_offer = false; 
        if (res == 1) {
            printf("Got a packet of length %d\n", header->len);
            // TODO: 在這裡解析 DHCP Offer
            struct dhcp_packet *dhcp = (struct dhcp_packet *)(pkt_data + ETHERNET_SIZE + IP_SIZE + UDP_SIZE);
            uint8_t *ip = (uint8_t *)&dhcp->yiaddr;
            printf("yiaddr = %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
            uint8_t *opt = dhcp->options;
            printf("Magic Cookie: %d %d %d %d\n", opt[0], opt[1], opt[2], opt[3]);
            uint8_t *messageType = dhcp_get_option(dhcp->options+4,53);
            uint8_t *srv = dhcp_get_option(dhcp->options +4, 54);
            if (srv) {
                printf("Server ID = %d.%d.%d.%d\n",
                    srv[0], srv[1], srv[2], srv[3]);
            }
            printf("message type:%d\n",messageType[0]);
            if (2 == (int) messageType[0]) {
                printf("receive dhcp offer.\n");
                // confirm dhcp server ip and yiaddr
                break;
            }
        }
    }

    //sned dhcp request
    ip -> identification = htons(0x5421);
    ip->crc = checksum((unsigned short *)ip, sizeof(struct ip_header)/2);

    


    pcap_close(fp);
    pcap_freealldevs(alldevs);
    return 0;
}
