/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* Custom methods */
int validate_checksum(uint8_t *packet, unsigned int offset, unsigned int length, uint16_t old_cksm);
int check_eth_len(uint8_t *packet, unsigned int len);
int check_ip_len_cs(uint8_t *pkt, unsigned int len);
int check_icmp_len_cs(uint8_t *pkt, int len);
void eth_header(sr_ethernet_hdr_t *eth_hdr, struct sr_if *interface, uint8_t *dest_mac);
void ip_header(sr_ip_hdr_t *ip_hdr, uint32_t src_ip, uint32_t dst_ip, uint16_t len, uint8_t ttl, uint8_t protocol);
void send_packet(struct sr_instance*, uint8_t*, unsigned int, struct sr_if*, uint32_t);
void send_icmp_msg(struct sr_instance*, uint8_t*, unsigned int, uint8_t, uint8_t);
void handle_arp(struct sr_instance *sr, uint8_t *pkt, char *interface, unsigned int len);
void handle_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface);
void forward_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface);
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr);

/* Custom method: convert IP int to string */
void addr_ip_int(char* buf, uint32_t ip);
int verify_ip(sr_ip_hdr_t*);
int verify_icmp(uint8_t*, unsigned int);

#endif /* SR_ROUTER_H */
