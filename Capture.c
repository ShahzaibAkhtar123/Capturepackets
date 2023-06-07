#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    unsigned short ip_hdr_len;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        ip_hdr_len = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr_len);
            printf("Packet Length: %d\n", pkthdr->len);
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
            printf("Protocol: TCP\n");
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_hdr_len);
            printf("Packet Length: %d\n", pkthdr->len);
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
            printf("Protocol: UDP\n");
        }

        // Print packet data
        printf("Packet Data:\n");
        for (int i = 0; i < pkthdr->len; i++) {
            printf("%02x ", packet[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    // Replace "eth0" with my network interface name (e.g., "wlan0" for wireless)
    char dev[] = "eth0";

    // Open the network interface for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}