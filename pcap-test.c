#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h> // for ntoh

// assignment--------------------
// Ethernet
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
// IP
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define IP_ADDR_LEN 4

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
// TCP
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TCP_IP 16
#define SIZE_TCP 16

/* Ethernet header */
typedef struct EthernetHeader{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
} EthernetHeader;

typedef struct IPHeader{
    u_char ip_vhl;          /* version << 4 | header length >> 2 */
    u_char ip_tos;          /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
    u_char ip_ttl;          /* time to live */
    u_char ip_p;            /* protocol */
    u_short ip_sum;         /* checksum */
    u_char ip_src[IP_ADDR_LEN]; /* source address */
    u_char ip_dst[IP_ADDR_LEN]; /* dest address */
} IPHeader;

typedef u_int tcp_seq;

typedef struct TCPHeader{
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
    u_char th_flags;
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
} TCPHeader;

// ------------------------------

void listntoh(u_char* list, int length){
    u_char tmp[length];
    for(int i =0; i < length; i++) {
        tmp[i] = list[length-1-i];
    }
    for(int i =0; i < length; i++) {
        list[i] = tmp[i];
    }
}

void printAddress(u_char* list, int length){
    for(int i=0; i<length ; i++){
        printf("%.2x ", list[i]);
    }
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv)){
        return -1;}


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
        const struct EthernetHeader *ethernet; /* The ethernet header */
        const struct IPHeader *ip; /* The IP header */
        const struct TCPHeader *tcp; /* The TCP header */
        const char * payload;   /*Packet payload*/
        u_int size_ip, size_tcp;
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        ethernet = (struct EthernetHeader*) packet;
        ip = (struct IPHeader*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        tcp = (struct TCPHeader*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = size_tcp = TH_OFF(tcp)*4;
        payload = (struct TCPHeader*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        if ((ntohs(ethernet->ether_type) == 0x0800) && (ip->ip_p == 0x06)) {    // IPv4 and TCP
            // Ethernet header : src mac / dst mac
            printf("%u bytes captured\n", header->caplen);
            printf("Src MAC : ");
            listntoh(ethernet->ether_shost, ETHER_ADDR_LEN);
            printAddress(ethernet->ether_shost, ETHER_ADDR_LEN);
            printf("\n");
            printf("Dst MAC : ");
            listntoh(ethernet->ether_dhost, ETHER_ADDR_LEN);
            printAddress(ethernet->ether_dhost, ETHER_ADDR_LEN);
            printf("\n");

            // IP header : src ip / dst ip
            printf("Src IP : ");
            listntoh(ip->ip_src, IP_ADDR_LEN);
            printAddress(ip->ip_src, IP_ADDR_LEN);
            printf("\n");
            printf("Dst IP : ");
            listntoh(ip->ip_dst, IP_ADDR_LEN);
            printAddress(ip->ip_dst, IP_ADDR_LEN);
            printf("\n");

            // TCP header : src port / dst port
            printf("Src port : %04x\n", ntohs(tcp->th_sport));
            printf("Dst port : %04x\n", ntohs(tcp->th_dport));

            // Payload : hex 8 bytes
            printf("Payload : ");
            printAddress(payload, 8);
            printf("\n");

        }


	}

	pcap_close(pcap);
}
