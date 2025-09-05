#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in localAddr;
    struct ip_mreq_source mreq;
    char buf[1024];
    int recvlen;

    char bind_IP[32];
    char include_IP[32];
    char group_IP[32];
    printf("Enter bind IP to send from: ");
    scanf("%31s", bind_IP);
    printf("Enter include IP:");
    scanf("%31s", include_IP);
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

    // 綁定本地端口（例如 5000）
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(5000);   // multicast 流會送到這個 port
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    BOOL reuse = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    if (bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        printf("bind failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 設定 IGMPv3，加入特定群組+來源
    mreq.imr_multiaddr.s_addr = inet_addr(group_IP);    // multicast group
    mreq.imr_sourceaddr.s_addr = inet_addr(include_IP); // source IP
    mreq.imr_interface.s_addr = inet_addr(bind_IP);   // local NIC (用你的實際 IP)

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
                   (char *)&mreq, sizeof(mreq)) < 0) {
        printf("IP_ADD_SOURCE_MEMBERSHIP failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Joined group, listening on port 5000...\n");

    // 持續接收封包
    while (1) {
        recvlen = recv(sock, buf, sizeof(buf), 0);
        if (recvlen > 0) {
            buf[recvlen] = '\0';
            printf("Received %d bytes: %s\n", recvlen, buf);
        } else if (recvlen == 0) {
            printf("Connection closed\n");
            break;
        } else {
            printf("recv failed: %d\n", WSAGetLastError());
            break;
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
