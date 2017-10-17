//
// Created by 김세희 on 2017. 10. 17..
//

#include "send_arp.h"

void print_mac(uint8_t *mac){
    printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}
void print_ip(uint8_t *_ip){
    char ipbuf[INET_ADDRSTRLEN];
    printf("%s\n",inet_ntop(AF_INET, _ip, ipbuf, sizeof(ipbuf)));
}

void send_arp(pcap_t *handle,uint8_t *my_ip,uint8_t *src_ip,uint8_t *dst_ip,uint8_t *my_mac, uint8_t *src_mac,uint8_t *dst_mac){

    arp_request(handle,my_mac,my_ip,src_ip,src_mac);
    arp_request(handle,my_mac,my_ip,dst_ip,dst_mac);

    arp_reply(handle,src_ip,dst_ip,my_mac,src_mac);

    puts("Success send arp!");
}

void arp_reply(pcap_t *handle,uint8_t *src_ip,uint8_t *dst_ip,uint8_t *my_mac, uint8_t *target_mac){
    struct libnet_arp_hdr *arp_h=(libnet_arp_hdr *)malloc(LIBNET_ARP_H);
    struct libnet_ethernet_hdr *eth_h=(libnet_ethernet_hdr *)malloc(LIBNET_ETH_H);
    struct my_ip_hdr *ip_h=(my_ip_hdr *)malloc(LIBNET_ARP_ETH_IP_H-LIBNET_ARP_H);
    uint8_t packet[200];

    memcpy(eth_h->ether_dhost,target_mac,ETHER_ADDR_LEN);
    memcpy(eth_h->ether_shost,my_mac,ETHER_ADDR_LEN);

    eth_h->ether_type=htons(0x0806);

    arp_h->ar_hrd=htons(1);    // hardware type : ethernet 1
    arp_h->ar_pro=htons(0x800);    // protocol type : IPv4 0x800
    arp_h->ar_hln=6;    // hardware size
    arp_h->ar_pln=4;    // protocol size
    arp_h->ar_op=htons(2);     // opcode : arp reply = 2

    memcpy(ip_h->sender_mac,my_mac,ETHER_ADDR_LEN);
    memcpy(ip_h->sender_ip,src_ip,4);
    memcpy(ip_h->target_mac,target_mac,ETHER_ADDR_LEN);
    memcpy(ip_h->target_ip,dst_ip,4);

    memcpy(packet,eth_h,LIBNET_ETH_H);
    memcpy(packet+LIBNET_ETH_H,arp_h,LIBNET_ARP_H);
    memcpy(packet+LIBNET_ETH_H+LIBNET_ARP_H,ip_h,MY_IP_HDR);

    for(int i=0;i<10;i++) {
        if(pcap_sendpacket(handle,packet,LIBNET_ETH_H + LIBNET_ARP_H + MY_IP_HDR)){
            printf("error");
        }
    }
}

void arp_request(pcap_t *handle,uint8_t *my_mac,uint8_t *my_ip,uint8_t *target_ip,uint8_t *target_mac){


    struct libnet_arp_hdr *arp_h=(libnet_arp_hdr *)malloc(LIBNET_ARP_H);
    struct libnet_ethernet_hdr *eth_h=(libnet_ethernet_hdr *)malloc(LIBNET_ETH_H);
    struct my_ip_hdr *ip_h=(my_ip_hdr *)malloc(LIBNET_ARP_ETH_IP_H-LIBNET_ARP_H);
    uint8_t packet[200];

    memset(eth_h->ether_dhost,0xff,6); // arp request's dest mac ff:ff:ff:ff:ff:ff
    memcpy(eth_h->ether_shost,my_mac,ETHER_ADDR_LEN);

    eth_h->ether_type=htons(0x0806);   //type : arp 0x0806

    arp_h->ar_hrd=htons(1);    // hardware type : ethernet 1
    arp_h->ar_pro=htons(0x800);    // protocol type : IPv4 0x800
    arp_h->ar_hln=6;    // hardware size
    arp_h->ar_pln=4;    // protocol size
    arp_h->ar_op=htons(1);     // opcode : arp request = 1
    memcpy(ip_h->sender_mac,my_mac,ETHER_ADDR_LEN);
    memcpy(ip_h->sender_ip,my_ip,4);
    memset(ip_h->target_mac,0,ETHER_ADDR_LEN);
    memcpy(ip_h->target_ip,my_ip,4);

    memcpy(packet,eth_h,LIBNET_ETH_H);
    memcpy(packet+LIBNET_ETH_H,arp_h,LIBNET_ARP_H);
    memcpy(packet+LIBNET_ETH_H+LIBNET_ARP_H,ip_h,MY_IP_HDR);
    for(int i=0;i<10;i++) {
        if(pcap_sendpacket(handle,packet,LIBNET_ETH_H + LIBNET_ARP_H + MY_IP_HDR)){
            printf("error");
        }
    }
    while(!receive_packet(handle,target_ip,target_mac));
    printf("target_mac ");
    print_mac(target_mac);

    return;

}

void my_info(uint8_t * mac_addr, uint8_t * ip,const char* if_name)
{
    ifaddrs* iflist;

    if (getifaddrs(&iflist) == 0) {
        for (ifaddrs* cur = iflist; cur; cur = cur->ifa_next) {
            if ((cur->ifa_addr->sa_family == AF_LINK) && (strcmp(cur->ifa_name, if_name) == 0) && cur->ifa_addr) {
                sockaddr_dl* sdl = (sockaddr_dl*)cur->ifa_addr;
                memcpy(mac_addr, LLADDR(sdl), sdl->sdl_alen);
            }
            if ((cur->ifa_addr->sa_family == AF_INET) && (strcmp(cur->ifa_name, if_name) == 0) && cur->ifa_addr) {
                memcpy(ip,&((struct sockaddr_in *)cur->ifa_addr)->sin_addr,4);
            }
        }

        freeifaddrs(iflist);
    }
    printf("my mac : ");
    print_mac(mac_addr);
    printf("my ip : ");
    print_ip(ip);
    return;
}


bool receive_packet(pcap_t* handle,uint8_t *target_ip,uint8_t *target_mac){

    struct pcap_pkthdr* header;
    const u_char* packet;
    struct libnet_ethernet_hdr *eth_h;
    struct libnet_arp_hdr *arp_h;
    struct my_ip_hdr *myip_h;


    int res = pcap_next_ex(handle, &header, &packet);

    if (res == -1 || res == -2)
        return 0;

    eth_h=(struct libnet_ethernet_hdr*)packet;
    arp_h=(struct libnet_arp_hdr*)(packet+LIBNET_ETH_H);
    if(htons(eth_h->ether_type)!=0x0806||htons(arp_h->ar_op)!=2){
        return 0;
    }
    else{
        myip_h=(struct my_ip_hdr*)(packet+LIBNET_ETH_H+LIBNET_ARP_H);
        if(!memcmp(myip_h->sender_ip,target_ip,ETHER_ADDR_LEN)) {
            memcpy(target_mac, myip_h->sender_mac, ETHER_ADDR_LEN);
            return 1;
        }
        else{
            return 0;
        }
    }

}