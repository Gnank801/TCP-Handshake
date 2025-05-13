#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t calculate_checksum(uint16_t *ptr, int nbytes) {
    long sum = 0;
    uint16_t oddbyte;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

void send_packet(int sock, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, 
                 uint32_t seq, uint32_t ack_seq, bool syn, bool ack) {
    
    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *ip = (struct iphdr *)datagram;
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in dest;
    struct pseudo_header psh;

    // Fill IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;

    // Fill TCP header
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack_seq);
    tcp->doff = 5;
    tcp->syn = syn;
    tcp->ack = ack;
    tcp->window = htons(8192);
    tcp->check = 0;

    // Pseudo header for checksum
    psh.src = src_ip;
    psh.dst = dst_ip;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[4096];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->check = calculate_checksum((uint16_t *)pseudo_packet, sizeof(psh) + sizeof(struct tcphdr));

    dest.sin_family = AF_INET;
    dest.sin_port = tcp->dest;
    dest.sin_addr.s_addr = dst_ip;

    if (sendto(sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto() failed");
    }
}

// Replace your main() function with this:
int main() {
    // Sending socket
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        perror("Raw socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Receiving socket
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0) {
        perror("Receive socket creation failed");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    uint32_t src_ip = inet_addr("127.0.0.1");
    uint32_t dst_ip = server_addr.sin_addr.s_addr;

    std::cout << "[+] Sending SYN packet..." << std::endl;
    send_packet(send_sock, src_ip, dst_ip, 54321, SERVER_PORT, 200, 0, true, false);

    // Now receive SYN-ACK using recv_sock
    char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    while (true) {
        int data_size = recvfrom(recv_sock, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("recvfrom() failed");
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buffer;
        struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl * 4);

        if (tcp->source == htons(SERVER_PORT) && tcp->dest == htons(54321)) {
            if (tcp->syn == 1 && tcp->ack == 1 && ntohl(tcp->seq) == 400 && ntohl(tcp->ack_seq) == 201) {
                std::cout << "[+] Received SYN-ACK. Sending ACK..." << std::endl;
                send_packet(send_sock, src_ip, dst_ip, 54321, SERVER_PORT, 600, 401, false, true);
                break;
            }
        }
    }

    std::cout << "[+] TCP Handshake complete!" << std::endl;
    close(send_sock);
    close(recv_sock);
    return 0;
}


