//
// Created by 김세희 on 2017. 10. 17..
//


#pragma once

#include <pcap.h>

#include <sys/socket.h>
#include <net/if.h>
#include<net/if_dl.h>
#include<netinet/in.h>
#include <cstring>
#include<sys/ioctl.h>
#include <ifaddrs.h>
#include <libnet.h>
#include <stdlib.h>

struct my_ip_hdr{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
#define MY_IP_HDR 20


void my_info(uint8_t *mac_addr, uint8_t *ip,const char* if_name);
void arp_request(pcap_t *handle,uint8_t *my_mac,uint8_t *my_ip,uint8_t *my_addr,uint8_t *target_mac);
int send_packet(pcap_t *handle,u_char *packet,int length);
bool receive_packet(pcap_t* handle,uint8_t* target_ip,uint8_t *target_mac);
void print_mac(uint8_t *mac);
void print_ip(uint8_t *ip);
void arp_reply(pcap_t *handle,uint8_t *src_ip,uint8_t *dst_ip,uint8_t *my_mac,uint8_t *target_mac);
void send_arp(pcap_t *handle,uint8_t *my_ip,uint8_t *src_ip,uint8_t *dst_ip,uint8_t *my_mac, uint8_t *src_mac,uint8_t *dst_mac);
