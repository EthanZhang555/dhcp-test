all:
	gcc main.c -IC:/npcap-sdk-1.15/Include -LC:/npcap-sdk-1.15/Lib -lwpcap -lpacket -o main.exe
	gcc list_ips.c -o list_ips.exe -IC:/npcap-sdk-1.15/Include -LC:/npcap-sdk-1.15/Lib -lwpcap -lPacket -lws2_32
	gcc dhcp_discover.c -IC:\npcap-sdk-1.15\Include -LC:\npcap-sdk-1.15\Lib -lwpcap -lPacket -lws2_32 -o dhcp_discover.exe
	gcc discover_request.c -IC:\npcap-sdk-1.15\Include -LC:\npcap-sdk-1.15\Lib -lwpcap -lPacket -lws2_32 -o discover_request.exe
clean:
	rm main.exe
	rm list_ips.exe