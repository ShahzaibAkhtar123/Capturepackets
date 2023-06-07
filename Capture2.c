#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <time.h> 

#define MAX_SERVICES 65536

typedef struct {
    int port;
    int count;
} Application;

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Application* applications = (Application*)userData;
    struct ethhdr* ethHeader = (struct ethhdr*)packet;
    struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ethhdr));

    if (ntohs(ethHeader->h_proto) == ETH_P_IP) {
        switch (ipHeader->ip_p) {
            case IPPROTO_TCP: {
                struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
                int srcPort = ntohs(tcpHeader->th_sport);
                int dstPort = ntohs(tcpHeader->th_dport);

                applications[srcPort].count++;  // Increment the count for the source port
                applications[dstPort].count++;  // Increment the count for the destination port
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr* udpHeader = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
                int srcPort = ntohs(udpHeader->uh_sport);
                int dstPort = ntohs(udpHeader->uh_dport);

                applications[srcPort].count++;  // Increment the count for the source port
                applications[dstPort].count++;  // Increment the count for the destination port
                break;
            }
            case IPPROTO_ICMP: {
                // Handle ICMP protocol if needed
                break;
            }
            default:
                break;
        }
    }
}

void displayApplicationStats(Application* applications) {
    int i;
    int totalPackets = 0;

    for (i = 0; i < MAX_SERVICES; i++) {
        totalPackets += applications[i].count;
    }

    printf("\nApplication stat\n");
    printf("Services\t| Count\t| Percentage\n");
    printf("-----------------------------------\n");

    for (i = 0; i < MAX_SERVICES; i++) {
        if (applications[i].count > 0) {
            float percentage = (applications[i].count / (float)totalPackets) * 100;
            printf("%-15d\t| %-6d\t| %.2f%%\n", applications[i].port, applications[i].count, percentage);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    Application applications[MAX_SERVICES] = { 0 };  // Initialize application counters to zero

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);  // Replace "eth0" with your network interface name

    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }

    // Set filter to capture IP packets only
    struct bpf_program fp;
    char filter_exp[] = "ip";
    pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    printf("Capturing network traffic...\n");

    // Capture packets for a specific duration (3 minutes in this case)
    time_t startTime = time(NULL);
    time_t duration = 600;  // 3 minutes
    time_t currentTime;

    while ((currentTime = time(NULL)) - startTime <= duration) {
        pcap_loop(handle, 1, packetHandler, (u_char*)applications);
    }

    // Display application statistics
    displayApplicationStats(applications);

    pcap_close(handle);

    return 0;
}
