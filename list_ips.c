#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>   
#pragma comment(lib, "ws2_32.lib")  

int main() {
    WSADATA wsa;
    pcap_if_t *alldevs, *d;
    pcap_addr_t *a;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 啟動 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return -1;
    }

    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        WSACleanup();
        return -1;
    }

    
    for (d = alldevs; d != NULL; d = d->next) {
        printf("Interface: %s\n", d->name);
        if (d->description)
            printf("  Description: %s\n", d->description);

        for (a = d->addresses; a != NULL; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                printf("  IPv4: %s\n", inet_ntoa(sin->sin_addr));
            }
        }
        printf("\n");
    }

    pcap_freealldevs(alldevs);
    WSACleanup();
    return 0;
}