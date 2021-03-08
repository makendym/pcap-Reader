#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "rtp.h"
#include "tftp.h"
/*
 * PCAP file reader and parser.
 * compile with: gcc pcap-reader.c -o pcap-reader -lpcap
 *
 */
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv) 
{
    
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filename[128];

    if (argc < 2) {
        printf("usage: pcap-reader capture-filename\n");
        return (-1);
    }
    strncpy(filename, argv[1], 127);
    filename[127] = '\0';       // guarantees null terminated

    // open capture file for offline processing
    descr = pcap_open_offline(filename, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live(%s) failed: %s\n", filename, errbuf); 
        return -2;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed: %s", pcap_geterr(descr));
        return -3;
    }

    printf("capture finished\n");

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{
   
    struct ether_header* ethhdr;
    u_char *ptr;//
    int protocol;
    int i;
    const struct ip *iphdr;
    const struct tcphdr *tcphdr;
    const struct udphdr *udphdr;
     
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    char ipVersion;
    u_int sourcePort, destPort;
    u_char *data;
   

   

    int dataLength = 0;
    int dataStrLen = 0;
    char dataStr[1600]; 

  /* TFTP specific */
	const struct tftphdr *tftphdr;
    char *tftp_strings[] = {"invalid", "write request",  "read request", "data packet",  "ACK", "ERROR"};
    static int tftp_port = 0;
    /*rtp specific*/
    const struct rtphdr *rtphdr;
    static int rtp_port = 0;


    // type casting
    ethhdr = (struct ether_header *)packet;
    ptr = ethhdr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf("Source Address:");
     do{
         // print the results
         printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
     }while(--i>0);
     printf("\n");

    ptr = ethhdr->ether_dhost;
     i = ETHER_ADDR_LEN;
     printf("Destination Address:");
     do{
         // print the results
         printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
     }while(--i>0);
     printf("\n");
     
     
    //IP
    if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
	    iphdr = (struct ip *)(packet + sizeof(struct ether_header));
	    inet_ntop(AF_INET, &(iphdr->ip_src), sourceIp, INET_ADDRSTRLEN);
	    inet_ntop(AF_INET, &(iphdr->ip_dst), destIp, INET_ADDRSTRLEN);
        protocol = iphdr->ip_p;
        char *proto = (protocol == 17)? "UDP" : "TCP";
        // print the results
         printf("Protocol:%s(%d)\nIP Source Address:%s\nIP Destination Address:%s\n", proto, protocol, sourceIp, destIp);
	    if (iphdr->ip_p == IPPROTO_TCP) {
		    tcphdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		    sourcePort = ntohs(tcphdr->th_sport);
		    destPort = ntohs(tcphdr->th_dport);
		    data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
		    dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            // print the results
            printf("TCP Source Port:%u\nTCP Destination Port:%d\n", sourcePort, destPort);
	    }
	    else if (iphdr->ip_p == IPPROTO_UDP) {
		    udphdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		    sourcePort = ntohs(udphdr->uh_sport);
		    destPort = ntohs(udphdr->uh_dport);
		    data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
		    dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
             // print the results
            printf("UDP Source Port:%u\nUDP Destination Port:%d\n", sourcePort, destPort);
            if (destPort == RTP_PORT || destPort == rtp_port || sourcePort == rtp_port){
                int marker;
                int sequence;
                int time;
                rtphdr = (struct rtphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
                marker = rtphdr->rh_mark;
                char *mark = (marker == 0)? "false": "true";
                sequence =ntohs(rtphdr->rh_seq);
                time = ntohl(rtphdr->rh_time);
                // print the results
                printf("RTP marker: %s\nsequence:%d\ntime: %d\n\n", mark, sequence, time);
                 if (destPort == RTP_PORT)  
                    rtp_port = sourcePort;     
                
               } 
	    }
        
        

	    if (destPort == TFTP_PORT || destPort == tftp_port || sourcePort == tftp_port) {
            int opcode;

	        tftphdr = (struct tftphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            opcode = ntohs(tftphdr->th_opcode);

            printf("\tTFTP Op (%d) %s\n", opcode, tftp_strings[opcode]);

            if (destPort == TFTP_PORT)
                tftp_port = sourcePort;
        }
    
#if 0
	    /* 
	     * convert non-printable characters, other than carriage return, line feed,
	     * or tab into periods when displayed.
	     */
	    for (int i = 0; i < dataLength; i++) {
		    if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
			    dataStr[dataStrLen] = (char)data[i];
		    } else {
			    dataStr[dataStrLen] = '.';
		    }
		    dataStrLen++;
	    }
	    if (dataLength > 0) {
		    printf("%s\n", dataStr);
	    }
#endif
    }
}
