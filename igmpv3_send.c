#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in mcastAddr;
    const char *message = "Hello Multicast!";
    int ttl = 4;   // multicast TTL (跨越幾個路由器)

    char bind_IP[32];
    char group_IP[32];
    printf("Enter bind IP to send from: ");
    scanf("%31s", bind_IP);
    printf("Enter group IP:");
    scanf("%31s", group_IP);

    // 初始化 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // 建立 UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket failed\n");
        WSACleanup();
        return 1;
    }

    BOOL reuse = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    struct in_addr local_if;
    local_if.s_addr = inet_addr(bind_IP);  // 你要用的 NIC IP
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&local_if, sizeof(local_if)) < 0)
    {
        printf("set ip failure\n");
        return 1;
    }
        

    // 設定 Multicast TTL
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   (char*)&ttl, sizeof(ttl)) < 0) {
        printf("setsockopt TTL failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 指定 multicast group address + port
    mcastAddr.sin_family = AF_INET;
    mcastAddr.sin_addr.s_addr = inet_addr(group_IP);  // multicast group
    mcastAddr.sin_port = htons(5000);                    // port 要和接收端一致

    // 傳送封包
    if (sendto(sock, message, (int)strlen(message), 0,
               (struct sockaddr*)&mcastAddr, sizeof(mcastAddr)) < 0) {
        printf("sendto failed\n");
    } else {
        printf("Sent multicast: %s\n", message);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
