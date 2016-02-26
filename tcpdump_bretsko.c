
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

// ethernet headers are always exactly 14 bytes
#define SIZE_ETHERNET 14


typedef struct MACarray{
    char **macs;
    u_int32_t * packets;
    size_t size;
    size_t capacity;
} MACarray;

typedef struct IParray{
    u_int32_t *ips;
    size_t size;
    size_t capacity;
} IParray;

pcap_t *handle;
MACarray * mac_array;
IParray * ip_array;

static int tcp_counter;
static int udp_counter;

void initMACarray(MACarray *a, size_t initialCapacity) {

    a->capacity = initialCapacity;
    a->size = 0;
    a->macs = (char **)calloc((a->capacity), sizeof(char *));
    a->packets = (u_int32_t *)calloc(a->capacity, sizeof(u_int32_t));
}

void freeMACarray(MACarray *a) {
    free(a->macs);
    a->macs = NULL;

    free(a->packets);
    a->packets = NULL;
    a->size = a->capacity = 0;
}


void process_MAC(struct MACarray *m, char *new_mac){

    u_int32_t mac_idx = 0;

    if (m->size == 0){
        m->macs[0] = new_mac;
        m->size++;
        return;
    }

    if (m->size == m->capacity ){
        char * expanded_char;
        u_int32_t *expanded_int;
        m->capacity *= 2;

        expanded_char = (char *)realloc(m->macs, (m->capacity +1) * sizeof(char));
        if(expanded_char == NULL){
            printf("Error was encountered during expansion of MAC array");
            return;
        } else {
            m->macs = expanded_char;
        }

        expanded_int = (u_int32_t *)realloc(m->packets, m->capacity * sizeof(u_int32_t));
        if(expanded_int  == NULL){
            printf("Error was encountered during expansion of packets array");
            return;
        }else{
            m->packets = expanded_int;
        }
    }

    while(!(strcmp(m->macs[mac_idx],new_mac) == 0) && mac_idx < m->size){
        ++mac_idx;
    }
    if (strcmp(m->macs[mac_idx],new_mac)){
        m->macs[m->size] = new_mac;
        m->packets[m->size]++;
        mac_idx = m->size;
        m->size++;
    } else {
        m->packets[mac_idx]++;
    }
}

void initIParray(IParray *a, size_t initialCapacity) {
    a->capacity = initialCapacity;
    a->size = 0;
    a->ips = (u_int32_t *)calloc(a->capacity, sizeof(u_int32_t));
}

void freeIParray(IParray *a) {
    free(a->ips);
    a->ips = NULL;
    a->size = a->capacity = 0;
}

void check_IParr_size (struct IParray *a){
    
    if (a->size == a->capacity) {
        u_int32_t *expanded_ips;
        a->capacity *= 2;

        expanded_ips = (u_int32_t *)realloc(a->ips, a->capacity * sizeof(u_int32_t));
        if(expanded_ips  == NULL){
            printf("Error was encountered during expansion of IPs packets");
            return;
        }else{
            a->ips = expanded_ips;
        }
    }
}

void add_IP(struct IParray *a, const struct iphdr* new_ip){
    uint32_t s_iter = 0;
    uint32_t d_iter = 0;
    int i= 0;
    bool found_src = false;
    bool found_dest = false;

    if (a->size == 0){
        a->ips[0] = new_ip->saddr;
        a->size++;
        return;
    }

    while (a->ips[i]){

        if(a->ips[s_iter] == new_ip->saddr)
        {
            s_iter++;
            found_src = true;
            break;
        }
        ++s_iter;
        ++i;
    }

    if (!found_src && (a->ips[s_iter] == 0)){
        check_IParr_size(a);
        a->ips[a->size] = new_ip->saddr;
        a->size++;
    }

    while (a->ips[i]){
        if(a->ips[d_iter] == new_ip->daddr)
        {
            d_iter++;
            found_dest = true;
            break;
        }
        ++d_iter;
        ++i;
    }

    if (!found_dest && (a->ips[d_iter]== 0)){
        check_IParr_size(a);
        a->ips[a->size] = new_ip->daddr;
        a->size++;
    }
}
u_int32_t *sort_rough (u_int32_t *array, u_int32_t n)
{
    u_int32_t i, j;
    for (i = 0; i < n; i++) {
        for (j = 0; j < (n-1); j++) {
            if ((uint8_t)array[j] > (uint8_t)array[j + 1]) {
                u_int32_t temp;
                temp = array[j + 1];
                array[j + 1] = array[j];
                array[j] = temp;
            }
        }
    }
    return array;
}

void print_stats(MACarray *m, IParray * a){
    static struct in_addr ip_address;

    a->ips = sort_rough(a->ips,a->size);

    printf("\nUnique IPs from this session:\n\n");
    for (uint8_t i = 0;i < a->size; i++){
        ip_address.s_addr = a->ips[i];
        printf("%d | %s\n",i, inet_ntoa(ip_address));
    }

    for (int i = 0;i < m->size; ++i){
        printf("\n%d packets were sent from MAC: %s\n",m->packets[i], m->macs[i]);
    }

    printf("\nTotal TCP packets sent: %d\nTotal UDP packets sent: %d\n",tcp_counter,udp_counter);
}


u_char* handle_IP
(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
 packet)
{
    const struct iphdr* ip;
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    add_IP(ip_array,ip);

    switch(ip->protocol) {
    case IPPROTO_TCP:
        tcp_counter++;
        break;
    case IPPROTO_UDP:
        udp_counter++;
        break;
    case IPPROTO_ICMP:
        break;
    case IPPROTO_IP:
        break;
    default:
        break;
    }
    return NULL;
}

u_int16_t handle_ethernet
(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
 packet)
{

    u_int caplen = pkthdr->caplen;
    struct ether_header *eptr;
    u_int16_t ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);
    char* source_mac = ether_ntoa((struct ether_addr*)eptr->ether_shost);
    process_MAC(mac_array,source_mac);
    return ether_type;
}

void handle_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    u_int16_t type = handle_ethernet(args,pkthdr,packet);
    if(type == ETHERTYPE_IP)
    {
        handle_IP(args,pkthdr,packet);
    }
}

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* session_handle;
    uint32_t  srcip, netmask;
    srcip = netmask = 0;
    struct bpf_program  bpf;

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }

    if ((session_handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    if (pcap_compile(session_handle, &bpf, bpfstr, 0, &netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(session_handle));
        return NULL;
    }

    if (pcap_setfilter(session_handle, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }
    return session_handle;
}


void capture_loop(pcap_t* handle, int packets, pcap_handler func)
{
    if (pcap_loop(handle, -1, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(handle));
}



int program_terminate(int signo)
{
    printf("\nCapture complete.\n");
    pcap_close(handle);
    print_stats(mac_array, ip_array);
    freeIParray(ip_array);
    freeMACarray(mac_array);
    return signo;
}

int main(int argc,char **argv)
{
    mac_array = malloc(sizeof(struct MACarray));
    ip_array = malloc(sizeof(struct IParray));
    initIParray(ip_array,10);
    initMACarray(mac_array,10);
    char interface[256] = "", bpfstr[256] = "";
    int packets = 0, c, i;

    while ((c = getopt (argc, argv, "hi:n:")) != -1)
    {
        switch (c)
        {
        case 'h':
            printf("Usage: %s [-h] [-i ] []\n", argv[0]);
            exit(0);
            break;
        case 'i':
            strcpy(interface, optarg);
            break;
        }
    }

    for (i = optind; i < argc; i++)
    {
        strcat(bpfstr, argv[i]);
        strcat(bpfstr, " ");
    }

    if ((handle = open_pcap_socket(interface, bpfstr)))
    {
        signal(SIGINT, program_terminate);
        signal(SIGTERM, program_terminate);
        signal(SIGQUIT, program_terminate);
        capture_loop(handle, packets, (pcap_handler)handle_packet);
    }
    return 0;
}

