//
// Created by 김세희 on 2017. 10. 17..
//

#pragma once

#include "send_arp.h"
#include <unistd.h>



struct spoof_arg{
    pcap_t *handle;
    uint8_t *src_ip;
    uint8_t *dst_ip;
    uint8_t *my_mac;
    uint8_t *dst_mac;
    uint8_t *src_mac;
};

#define THREAD_N 100
#define infect_time 10



void f_arpspoof(pcap_t *handle,spoof_arg *sa,int pair);
void *infect(void *arg);
bool spoof_packet(pcap_t* handle, spoof_arg *sa, int pair);
