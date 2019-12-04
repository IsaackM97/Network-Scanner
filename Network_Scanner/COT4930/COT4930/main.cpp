//
//  main.cpp
//  COT4930
//
//  Created by Isaack Morales on 4/5/19.
//  Copyright © 2019 Isaack Morales. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <cstring>
#include <map>
#include <math.h>
#include <list>
#include <time.h>

//#include <sys/socket.h>
//#include <netinet/in.h>

//#include <netinet/ether.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <errno.h>
//#include "jansson.h"
#include <iostream>
#include <string>
#include <fstream>
//#include "backend.h"
#include <sstream>
#include <cstdio>
#include <string>
#include <stdio.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_map>

int packet_count;

using namespace std;

FILE * pFile;
char *command;


struct Data {  //place information in the table
    int numPackets; //number of packets
    int type;   //protocol name
};

unordered_map<u_int32_t, Data > table; //hash table

#ifndef iphdr
struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error  "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    //The options start here.
};
#endif



void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct ip *ip;
    struct tcphdr *tcp; //protocol name
    struct udphdr *udp; //protocol name
    struct icmphdr *icmp;
    u_int32_t src; //source IP
    u_int32_t dst; //destination IP
    u_int16_t dstPort; //source port
    u_int16_t srcPort; //destination port
    char prtcl[10];
    
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ether_header)); //extract IP Layer information from the packets
    ip   = (struct      ip*)(packet+sizeof(struct ether_header)); //extracts IP layer info
    dst = ntohl(iph->daddr);  //extracts destination IP address //iph is IP header
    src = ntohl(iph->saddr); //extracts source IP address
    
    //ntohl makes  the data in the file into 32 bits
    switch(iph->protocol)//checks to see what protocol we are filtering
    {
        case IPPROTO_ICMP:    // ICMP //if protocol is ICMP
        {
            icmp = (struct icmphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
            dstPort = 0;  //ICMP does not have destination or source ports
            srcPort = 0;
            strcpy(prtcl , "ICMP");
            break;
        }
        case IPPROTO_UDP: // UDP //if protocol is UDP
        {
            udphdr *udp = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            dstPort = udp->uh_dport; //retrieves destination port
            srcPort = udp->uh_sport; //retrieves source port
            strcpy(prtcl , "UDP");
            break;
        }
        case IPPROTO_TCP: // TCP //If protocol is TCP
        {
            tcphdr *tcp = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            dstPort = tcp->th_dport;
            srcPort = tcp->th_sport;
            strcpy(prtcl , "TCP");
            break;
        }
        default:
            // do nothing
            break;
            
    }
    char ipsrc[16];
    inet_ntop(AF_INET, &src, ipsrc, 16); //converts source IP from long integers into strings
    char ipdst[16];
    inet_ntop(AF_INET, &dst, ipdst, 16); //converts destination IP from long integers into strings
 //   printf("%s   %s : %d --> %s : %d \n", prtcl , ipsrc , ntohs(srcPort), ipdst, ntohs(dstPort) );
    //prints the name of the protocol, source IP address, source port, destination IP, and destination port
    
    
    packet_count++;
    if (packet_count % 100000 == 0) //reports by the number of packets by 1000
    {
        printf("number of processed packets %d \n", packet_count);
    }
    
    //hash table
    unordered_map<u_int32_t, Data >::iterator value = table.find(src);
    if(value == table.end()){ //if the source IP does not exsist
        Data data; //create "data" object
        data.numPackets = 1; //assigned the value of the packets read
        data.type = 53;  //assign the data type for the specific UDP packet (protocol)
        table.insert({ src, data }); //inserts the source IP and information into the "data" object
        //does not exist
        // add this to the table
    }else{
       
        value->second.numPackets = value->second.numPackets+1; //increments the number of packets read by 1 if packet exsists in table already
       
        //the key exsits
        // get the value and increment the value and put back in the table
    }
    

}

/* main function */
int main(int argc, char *argv[])
{
    packet_count = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *pcap_file;
    clock_t begin = clock();
    pcap_t *p;
    
    pcap_file = "/Users/IsaackMorales/Desktop/14.pcap";
    
    pcap_t *handle; //pcap handler to handle pcap file
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    struct bpf_program filter;      // Berekley Packet Filter
    char filter_exp[] = "udp dst port 53";
    //UDP network protocols that are prone to amplification attacks
    
    // DNS pakcets "udp dst port 53";
    // SNMP packets "udp dst port 161";
    // NTP packets "udp dst port 123";
    //Net Bios Packets "udp dst port 137";
    //SSDP packets "udp dst port 1900";
    //Char Gen Packets "udp dst port 19";
    //QOTD packets "udp dst port 17";
    //Quake 3 packets "udp dst port 27960";
    //Steam packets "udp dst port 27015";
    
    FILE *fp;
    //fp = myfopen(pcap_file, "r");
    fp = fopen(pcap_file, "r"); //opens pcap file
    
    p = pcap_fopen_offline(fp, errbuf);
    if (p == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        getchar();
        return 2;
    }
    if (pcap_compile(p, &filter, filter_exp, 0, 0) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(p));
        return 2;
    }
    if (pcap_setfilter(p, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(p));
        return 2;
    }
    printf("Capturing packets...\n");
    
    // Loops through packets and then closes PCAP //
   
    pcap_loop(p, 1000000, packetHandler, NULL); //-1 goes through whole packet
    //runs through 1 million packets
    
    // Traversing an unordered map
    for (auto x : table) //reading rows of table
        cout << "source IP: " << x.first << " numberOfPackets: " << x.second.numPackets << " type: " << x.second.type << endl; //prints source IP and information
    
    pcap_close(p); //closes pcap file
    
    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("This is the time take %f \n", time_spent);
    printf("Serializing flows...\n");
    
    
    
    fclose(pFile);
    
    
    
}
