#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define MAX_PACKETS 10000

typedef struct {
    unsigned int count;
    char* name;
} AppStats;

AppStats appStats[MAX_PACKETS];

void processPacket(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct ip *iph = (struct ip *)(packet + sizeof(struct ethhdr));

    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
        unsigned int sport = ntohs(tcph->source);
        unsigned int dport = ntohs(tcph->dest);

        // Check for specific ports of interest
        if (sport == 80 || dport == 80) {
            appStats[0].count++;  // Web service
        } else if (sport == 443 || dport == 443) {
            appStats[1].count++;  // HTTPS service
        } else if (sport == 22 || dport == 22) {
            appStats[2].count++;  // SSH service
        } else if (sport == 53 || dport == 53) {
            appStats[3].count++;  // DNS service
        } else if (sport == 25 || dport == 25) {
            appStats[4].count++;  // SMTP service
        }
    }
}

void printAppStats() {
    for (int i = 0; i < MAX_PACKETS; i++) {
        if (appStats[i].count > 0) {
            printf("Application: %s, Packet Count: %u\n", appStats[i].name, appStats[i].count);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;

    // Open the network interface for capturing
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Initialize the application stats
    appStats[0].count = 0;
    appStats[0].name = "Web Service";
    appStats[1].count = 0;
    appStats[1].name = "HTTPS Service";
    appStats[2].count = 0;
    appStats[2].name = "SSH Service";
    appStats[3].count = 0;
    appStats[3].name = "DNS Service";
    appStats[4].count = 0;
    appStats[4].name = "SMTP Service";

    // Start capturing packets and process them in real-time
    while (1) {
        packet = pcap_next(handle, &header);
        processPacket(NULL, &header, packet);
        printAppStats();
    }

    // Close the capture handle
    pcap_close(handle);

    return 0;
}