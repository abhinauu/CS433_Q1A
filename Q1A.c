#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#define PACKET_BUFFER_SIZE 65536
int count=0;

void process_packet(unsigned char *, int);

int main() {
    int raw_socket;
    struct sockaddr server;
    socklen_t server_len = sizeof(server);
    unsigned char packet_buffer[PACKET_BUFFER_SIZE];

    // Create a raw socket to capture all packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket == -1) {
        perror("Socket creation error");
        exit(1);
    }

    // Receive packets and print information
    while (1) {
        int packet_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, &server, &server_len);
        if (packet_size == -1) {
            perror("Packet receive error");
            close(raw_socket);
            exit(1);
        }

        process_packet(packet_buffer, packet_size);
    }

    close(raw_socket);
    //printf("Total observed = %d\n", count);
    return 0;
}

void process_packet(unsigned char *packet, int packet_size) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses to human-readable format
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    // Print source and destination IP addresses and ports
    printf("Source IP: %s\n", src_ip);
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination IP: %s\n", dest_ip);
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    printf("Count no. : %d\n", count);
    count++;
    printf("\n");
}