// snoof.c
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>

//TCP flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN];  //dst host address
    u_char ether_shost[ETHER_ADDR_LEN];  //src host address
    u_short ether_type;                  //type of packet, could be IP, ARP, etc.
};

struct icmpheader
{
    unsigned char icmp_type;  // ICMP message type
    unsigned char icmp_code;  // Error code
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};

struct ipheader
{
      unsigned char ip_ihl:4, //  4 bits, IP header length
                    ip_ver:4; //  4 bits, IP version
      unsigned char iph_tos;  //  8 bits, Type of service
      unsigned short int iph_len; // 16 bits, IP packet length
      unsigned short int iph_ident; // 16 bits, identification
      unsigned short int iph_flag:3,  // fragmentation flags
                         iph_offset:13; //flag offset
      unsigned char iph_ttl;   // 8 bits, time to live
      unsigned char iph_protocol; //protocol type
      unsigned short int iph_chksum;
      struct in_addr iph_sourceip;   //source IP address
      struct in_addr iph_destip;     //destination iP address
};

//UDP header
struct udpheader
{
    u_int16_t udp_sport;
    u_int16_t udp_dport;
    u_int16_t udp_ulen;
    u_int16_t udp_sum;
};


/* TCP header */
struct tcpheader {
   uint16_t src_port;
   uint16_t dst_port;
   uint32_t seq;
   uint32_t ack;
   uint8_t  data_offset;  // 4 bits
   uint8_t  flags;
   uint16_t window_size;
   uint16_t checksum;
   uint16_t urgent_p;
};


void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_destip;
    sendto(sock, ip, ntohs(ip->lph_len), 0, (struct sockaddr *) &dest_info, sizeof(dest_info));
    close(sock);
}



void spoof_reply_udp(struct ipheader* ip)
{
    const char buffer[1500];
    int ip_header_len = ip->ip_ihl * 4;
    struct udpheader * udp = (struct udpheader *) ((u_char *) ip + ip_header_len);
    if (ntohs(udp->udp_dport) != 9999)
        return;

    //step 1: make a copy from the original packet
    memset((char *)buffer, 0, 1500);
    memcpy((char *)buffer, ip, ntohs(ip->iph_len));
    struct ipheader *newip = (struct ipheader *) buffer;
    struct udpheader *newudp = (struct udpheader *) (buffer + ip_header_len);
    char *data = (char *)newudp + sizeof(struct udpheader);

    //step2: construct the UDP payload, keep track of payload size
    const char *msg = "This is a spoofed reply!\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    //step3: construct the UDP header
    newudp->udp_sport = udp->udp_dport;
    newudp->udp_dport = udp->udp_sport;
    newudp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    newudp->udp_sum = 0;

    //step4: Construct IP header
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 50;
    newip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);

    //step 5: send the packet
    send_raw_ip_packet(newip);
}


void spoof_reply_tcp(struct ipheader* ip)
{
    const char buffer[1500];
    int ip_header_len = ip->ip_ihl * 4;
    struct tcpheader * tcp = (struct tcpheader *) ((u_char *) ip + ip_header_len);
    if (ntohs(tcp->dst_port) != 9999)
        return;

    //step 1: make a copy from the original packet
    memset((char *)buffer, 0, 1500);
    memcpy((char *)buffer, ip, ntohs(ip->iph_len));
    struct ipheader *newip = (struct ipheader *) buffer;
    struct tcpheader *newtcp = (struct tcpheader *) (buffer + ip_header_len);
    char *data = (char *)newtcp + sizeof(struct tcpheader);

    //step2: construct the UDP payload, keep track of payload size
    const char *msg = "This is a spoofed TCP reply!\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    //step3: construct the UDP header
    newtcp->src_port = tcp->dst_port;
    newtcp->dst_port = tcp->src_port;
    newtcp->seq = tcp->seq;
    newtcp->ack = htons(ntohs(tcp->seq) + data_len);

    //step4: Construct IP header
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 50;
    newip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader) + data_len);

    //step 5: send the packet
    send_raw_ip_packet(newip);
}

void spoof_reply_icmp(struct ipheader* ip)
{
  char buffer[1500];
  memset(buffer, 0, 1500);

  struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8;    // 8 is request
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_cksum((unsigned short *) icmp, sizeof(struct icmpheader));

  //step 2: fill in the IP header
  // use the same ipheader struct as before
  struct ipheader *newip = (struct ipheader *) buffer;
  newip->iph_ver = ip->iph_ver;
  newip->iph_ihl = ip->iph_ihl;
  newip->iph_ttl = 20;
  newip->iph_sourceip.s_addr = ip->iph_destip.s_addr;
  newip->iph_destip.s_addr = ip->iph_sourceip.s_addr;
  ip->iph_protocol = IPPROTO_ICMP;
  ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader)); 

  //step3: send spoofed packet
  send_raw_ip_packet(ip);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *) packet;
  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct etherheader));
    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("To: %s\n", inet_ntoa(ip->iph_destip));

    switch (ip->iph_protocol) {
      case IPPROTO_TCP:
        printf("TCP connection received \n");
        // TCP spoof reply
        spoof_reply_tcp(ip);
        return;

      case IPPROTO_UDP:
        printf("UDP connection received \n");
        spoof_reply_udp(ip);
        return;

      case IPPROTO_ICMP:
        printf("ICMP packets received \n");
        spoof_reply_icmp(ip);
        return;

      default:
        printf("unknown packet type\n");
        return;
    }
  }
}



int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";   // only accept icmp packets
    bpf_u_int32 net;

    //step 1: open live pcap session on NIC with name eth3
    handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf);

    //step 2: compile filter_exp into BPF pseudo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    //step 3: capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
