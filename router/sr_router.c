/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/* Custom method: convert IP int to string */
/* Basically modified from 'print_addr_ip_int' above */
void addr_ip_int(char* buf, uint32_t ip) {
    sprintf(
        buf,
        "%d.%d.%d.%d",
        ip >> 24,
        (ip << 8) >> 24,
        (ip << 16) >> 24,
        (ip << 24) >> 24
    );
}

/* Custom method: sanity-check IP packet */
int verify_ip(sr_ip_hdr_t* ip_hdr) {
  /* store the received checksum */
  uint16_t received_checksum = ip_hdr->ip_sum;
  /* make checksum zero to calculate the true checksum */
  ip_hdr->ip_sum = 0;
  uint16_t true_checksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  ip_hdr->ip_sum = received_checksum;
  /* compare the received checksum and the value it should be */
  if(received_checksum != true_checksum) {
      printf("Error: verify_ip: checksum didn't match.\n");
      return -1;
  }
  /* verify the length of IP packet */
  if(ip_hdr->ip_len < 20) {
      printf("Error: verify_ip: IP packet too short.\n");
      return -1;
  }

  return 0;
}

/* Custom method: sanity-check ICMP packet */
int verify_icmp(uint8_t* packet, unsigned int len) {
  uint8_t* payload = (packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)payload;

  /* verify the length of header */
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) + (ip_hdr->ip_hl * 4)) {
    printf("Error: verify_icmp: header too short.\n");
    return -1;
  }

  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* verify the checksum */
  uint16_t received_checksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t true_checksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
  icmp_hdr->icmp_sum = received_checksum;
  if(received_checksum != true_checksum) {
    printf("Error: verify_icmp: checksum didn't match.\n");
    return -1;
  }

  return 0;
}

/* Custom method: find the routing table entry which has the longest matching prefix with the destination IP addr */
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip) {
    struct sr_rt* longest_prefix_entry = NULL;

    char ip_string[15];
    addr_ip_int(ip_string, ntohl(ip));
    fprintf(stderr, "Finding longest prefix for %s ...\n", ip_string);

    struct sr_rt* table_entry = sr->routing_table;
    while(table_entry) {
        /* check if the prefix matches our IP */
        if((table_entry->dest.s_addr & table_entry->mask.s_addr) == (ip & table_entry->mask.s_addr)) {
            /* check whether to update the longest_prefix_entry */
            if(!longest_prefix_entry || table_entry->mask.s_addr > longest_prefix_entry->mask.s_addr) {
                longest_prefix_entry = table_entry;
            }
        }
        table_entry = table_entry->next;
    }

    /* print the result */
    if(longest_prefix_entry) {
        char dest_string[15];
        addr_ip_int(dest_string, ntohl(longest_prefix_entry->dest.s_addr));
        char gw_string[15];
        addr_ip_int(gw_string, ntohl(longest_prefix_entry->gw.s_addr));
        char mask_string[15];
        addr_ip_int(mask_string, ntohl(longest_prefix_entry->mask.s_addr));
        printf(
            "Found longest matching prefix: {dest:\"%s\",gw:\"%s\",mask:\"%s\",interface:\"%s\"}.\n",
            dest_string,
            gw_string,
            mask_string,
            longest_prefix_entry->interface
        );
    } else {
        printf("Cannot find any longest matching prefix.\n");
    }

    return longest_prefix_entry;
}


/* Custom method: send packet to next_hop_ip, according to "sr_arpcache.h"
 * Check the ARP cache, send packet or send ARP request */
void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* interface, uint32_t dest_ip) {
    struct sr_arpentry* arp_cached = sr_arpcache_lookup(&sr->cache, dest_ip);

    if(arp_cached) {
        /* if cached, send packet through outgoing interface */
        printf("ARP mapping cached.\n");
        sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
        /* set destination MAC to the mapped MAC */
        memcpy(ehdr->ether_dhost, arp_cached->mac, ETHER_ADDR_LEN);
        /* set the source MAC to the outgoing interface's MAC */
        memcpy(ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, interface->name);
        free(arp_cached);
    } else {
        /* if not cached, send ARP request */
        printf("Queue ARP request.\n");
        struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
        handle_arp_request(sr, arpreq);
    }
}

/* Custom method: send an ICMP message */
void send_icmp_msg(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code) {
    /* New packet illustration:
                |<- Ethernet hdr ->|<- IP hdr ->|<- ICMP hdr ->|
                ^
             *packet
    */
    /* construct ethernet header from packet */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    /* construct IP header from packet */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* get longest matching prefix of source IP */
    struct sr_rt* rt_entry = longest_prefix_match(sr, ip_hdr->ip_src);

    if(!rt_entry) {
        printf("Error: send_icmp_msg: routing table entry not found.\n");
        return;
    }

    /* get outgoing interface */
    struct sr_if* interface = sr_get_interface(sr, rt_entry->interface);

    switch(type) {
        case 0: {

            /* this ICMP message is a sending-back */
            uint32_t temp = ip_hdr->ip_dst;
            ip_hdr->ip_dst = ip_hdr->ip_src;
            ip_hdr->ip_src = temp;
            /* not necessary to recalculate checksum here */

            /* set ethernet header source MAC & destination MAC: 00-00-00-00-00-00 */
            memcpy(eth_hdr->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
            
            /* construct ICMP header */
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;

            /* compute ICMP checksum */
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
            
            send_packet(sr, packet, len, interface, rt_entry->gw.s_addr);
            break;
        }
        case 11:
        case 3: {
            /* calculate length of the new ICMP packet (illustrated above) */
            unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            /* construct new ICMP packet */
            uint8_t* new_packet = malloc(new_len);

            /* sanity check */
            assert(new_packet);

            /* construct ethernet hdr */
            sr_ethernet_hdr_t* new_eth_hdr = (sr_ethernet_hdr_t*)new_packet;
            /* construct IP hdr */
            sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
            /* construct type 3 ICMP hdr */
            sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));


            /* set new IP hdr */
            new_ip_hdr->ip_v    = 4;
            new_ip_hdr->ip_hl   = sizeof(sr_ip_hdr_t) / 4;
            new_ip_hdr->ip_tos  = 0;
            new_ip_hdr->ip_len  = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            new_ip_hdr->ip_id   = htons(0);
            new_ip_hdr->ip_off  = htons(IP_DF);
            new_ip_hdr->ip_ttl  = 255;
            new_ip_hdr->ip_p    = ip_protocol_icmp;
            /* if code == 3 (i.e. UDP arrives destination), set source IP to received packet's destination IP */
            /* if others, set source IP to outgoing interface's IP */
            new_ip_hdr->ip_src = code == 3 ? ip_hdr->ip_dst : interface->ip;
            /* set destination IP to received packet's source IP */
            new_ip_hdr->ip_dst = ip_hdr->ip_src;
            
            /* set new ethernet header source MAC & destination MAC: 00-00-00-00-00-00 */
            memcpy(new_eth_hdr->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
            
            /* set protocol type to IP */
            new_eth_hdr->ether_type = htons(ethertype_ip);

            /* recalculate checksum */
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            /* set type 3 ICMP hdr */
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            send_packet(sr, new_packet, new_len, interface, rt_entry->gw.s_addr);
            free(new_packet);
            break;
        }
    }
}

/*---------------------------------------------------------------------
 * handles arp request and reply
 *---------------------------------------------------------------------*/
void handle_arp(struct sr_instance *sr, uint8_t *pkt, char *interface, unsigned int len) {
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    /* Get the interface associated with the incoming ARP request's target IP */
    struct sr_if *my_if = sr_get_interface_by_IP(sr, arp_hdr->ar_tip);

    if (my_if) {
        if (ntohs(arp_hdr->ar_op) == arp_op_request) {
            /*ARP Request*/

            /*Get the interface for the incoming ARP request*/
            struct sr_if *in_if = sr_get_interface(sr, interface);

            /*Construct ARP Reply*/
            uint8_t *reply_pkt = malloc(len);
            memcpy(reply_pkt, pkt, len);

            sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)(reply_pkt);
            memcpy(reply_eth_hdr->ether_dhost, reply_eth_hdr->ether_shost,  sizeof(uint8_t) * ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr->ether_shost, in_if, sizeof(uint8_t) * ETHER_ADDR_LEN);

            sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));
            reply_arp_hdr->ar_op = htons(arp_op_reply);
            memcpy(reply_arp_hdr->ar_sha, in_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            reply_arp_hdr->ar_sip = in_if->ip;
            memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
            reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

            send_packet(sr, reply_pkt, len, in_if, arp_hdr->ar_sip);
            free(reply_pkt);

        } else if (htons(arp_hdr->ar_op) == arp_op_reply) {
            /*ARP Reply*/
            /*Update Arp cache*/
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            if(req) {
                struct sr_packet* packet = req->packets;

                struct sr_if* in_interface;
                sr_ethernet_hdr_t* eth_hdr;

                /*Send Outstanding packets*/
                while(packet) {
                    in_interface = sr_get_interface(sr, packet->iface);
                    if(in_interface) {
                        eth_hdr = (sr_ethernet_hdr_t*)(packet->buf);
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, in_interface->addr, ETHER_ADDR_LEN);
                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                    }
                    packet = packet->next;
                }
                sr_arpreq_destroy(&sr->cache, req);
            }
        } else {
            printf("Unrecognized ARP OP Code.\n");
            return;
        }
    }else {
        printf("No matching interface found.\n");
    }
}

/*---------------------------------------------------------------------
 * handles ip packet
 *---------------------------------------------------------------------*/
void handle_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    if (!check_ip_len_cs(pkt, len)) {
        printf("Packet is not valid.\n");
        return;
    }

    /* Check if the incoming packet is destined for this interface */
    struct sr_if *my_if = sr_get_interface_by_IP(sr, ip_hdr->ip_dst);

    if(my_if) {
        if (ip_hdr->ip_p == 0x0001) {
            printf("Received ICMP packet.\n");

            /* ICMP */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (icmp_hdr->icmp_type != 8 || !check_icmp_len_cs(pkt, len)) {
                /* Unsupported type*/
                printf("Received unsupported type.\n");
                return;
            }
            /*Send ICMP echo reply*/
            send_icmp_msg(sr, pkt, len, 0, (uint8_t)0);       
        } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
            /* TCP/UDP */
            /* send error code 3, type 3*/
            send_icmp_msg(sr, pkt, len, 3, 3);
            return;
        } else {
            /* Unsupported Protocol */
            printf("Received unsupported protocol.\n");
            return ;
        }
    } else {
        /* forward */
        forward_ip(sr, pkt, len, interface);
    }
}

/*---------------------------------------------------------------------
 * Forward packet using longest prefix match
 *---------------------------------------------------------------------*/
void forward_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface) {
    /* construct IP hdr (bypass Ethernet hdr) */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(pkt + sizeof(sr_ethernet_hdr_t));

    /* decrease TTL */
    ip_hdr->ip_ttl--;
    if(ip_hdr->ip_ttl == 0) {
        printf("TTL decreased to zero.\n");
        send_icmp_msg(sr, pkt, len, 11, (uint8_t)0);
        return;
    }

    /* recalculate checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

    /* lookup destination IP in routing table */
    struct sr_rt* table_entry = longest_prefix_match(sr, ip_hdr->ip_dst);
    if(!table_entry) {
        printf("Error: handle_ip: destination IP not existed in routing table.\n");
        send_icmp_msg(sr, pkt, len, 3, 0);
        return;
    }

    /* find routing table indicated interface */
    struct sr_if* rt_out_interface = sr_get_interface(sr, table_entry->interface);
    if(!rt_out_interface) {
        printf("Error: handle_ip: interface \'%s\' not found.\n", table_entry->interface);
        return;
    }

    send_packet(sr, pkt, len, rt_out_interface, table_entry->gw.s_addr);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d\n", len);

    /* fill in code here */

    /* sanity check the incoming Ethernet packet */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        printf("Error: sr_handlepacket: Ethernet packet too short.\n");
        return;
    }

    switch (ethertype(packet)) {
        /* ARP packet */
        case ethertype_arp: {
            printf("Received ARP packet.\n");
            handle_arp(sr, packet, interface, len);
            break;
        }
        /* IP packet */
        case ethertype_ip: {
            printf("Received IP packet.\n");
            handle_ip(sr, packet, len, interface);
            break;
        }
    }
}/* end sr_ForwardPacket */

/*--------------------------------------------------------------------- 
 * checkers: Return 1 if valid, 0 if not.
 *---------------------------------------------------------------------*/
/* Common checksum validation function */
int validate_checksum(uint8_t *packet, unsigned int offset, unsigned int length, uint16_t old_cksm) {
  uint16_t new_cksm = cksum(packet + offset, length);
  return (old_cksm == new_cksm);
}

/* check eth length*/
int check_eth_len(uint8_t *packet, unsigned int len) {
  return (len >= sizeof(sr_ethernet_hdr_t));
}

/* check IP packet length and checksum*/
int check_ip_len_cs(uint8_t *pkt, unsigned int len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  uint16_t old_cksm = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;

  int valid = validate_checksum(pkt, sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t), old_cksm);
  ip_hdr->ip_sum = old_cksm;

  return valid;
}

/* check ICMP packet length and checksum*/
int check_icmp_len_cs(uint8_t *pkt, int len) {
  if (len < sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0;
  }

  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t old_cksm = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  int valid = validate_checksum(pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t), old_cksm);
  icmp_hdr->icmp_sum = old_cksm;

  return valid;
}

/*--------------------------------------------------------------------- 
 * Helper function to prepare Ethernet and IP header
 *---------------------------------------------------------------------*/
/* Helper function to prepare Ethernet header */
void eth_header(sr_ethernet_hdr_t *eth_hdr, struct sr_if *interface, uint8_t *dest_mac) {
  memcpy(eth_hdr->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, dest_mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);
}

/* Helper function to prepare IP header */
void ip_header(sr_ip_hdr_t *ip_hdr, uint32_t src_ip, uint32_t dst_ip, uint16_t len, uint8_t ttl, uint8_t protocol) {
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_len = htons(len);
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = ttl;
  ip_hdr->ip_p = protocol;
  ip_hdr->ip_src = src_ip;
  ip_hdr->ip_dst = dst_ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

/* ----------------------------------------------- */
