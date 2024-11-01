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

  printf("*** -> Received packet of length %d \n",len);

  if (!check_eth_len(packet, len)) {
        printf("Packet invalid.\n");
        return;
    }

    switch (ethertype(packet)) {
        case ethertype_arp:
            printf("Received ARP packet.\n");
            handle_arp(sr, packet, interface, len);
            break;
        case ethertype_ip:
            printf("Received IP packet.\n");
            handle_ip(sr, packet, len, interface);
            break;
    }
}/* end sr_ForwardPacket */

/* ----------------------------------------------- */

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

/* ----------------------------------------------- */

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

            lookup_and_send_packet(sr, arp_hdr->ar_sip, reply_pkt, len, in_if);
            free(reply_pkt);

        } else if (htons(arp_hdr->ar_op) == arp_op_reply) {
            /*ARP Reply*/
            /*Update Arp cache*/
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            if (req) {
                struct sr_packet *iterator = req->packets;

                struct sr_if* in_interface;
                sr_ethernet_hdr_t* eth_hdr;

                /*Send Outstanding packets*/
                while (iterator) {
                    in_interface = sr_get_interface(sr, iterator->iface);
                    if(in_interface) {
                        eth_hdr = (sr_ethernet_hdr_t*)(iterator->buf);
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, in_interface->addr, ETHER_ADDR_LEN);
                        sr_send_packet(sr, iterator->buf, iterator->len, iterator->iface);
                    }
                    iterator = iterator->next;
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

    if (my_if) {
        if (ip_hdr->ip_p == 0x0001) {
            printf("Received ICMP packet.\n");

            /* ICMP */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (icmp_hdr->icmp_type != 8 || !check_icmp_len_cs(pkt, len)) {
                /* Unsupported type*/
                printf("Received unsupported type.\n");
                return ;
            }
            /*Send ICMP echo reply*/
            send_icmp_echo_reply(sr, pkt, len);       
        } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
            /* TCP/UDP */
            /* send error code 3, type 3*/
            send_icmp_error(sr, pkt, len, 3, 3);
            return;
        } else {
            /* Unsupported Protocol */
            printf("Received unsupported protocol.\n");
            return ;
        }
    } else {
        /* forward */
        forward_ip(sr, pkt, len);
    }
}

/*---------------------------------------------------------------------
 * Forward packet using longest prefix match
 *---------------------------------------------------------------------*/
void forward_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len) {
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(pkt + sizeof(sr_ethernet_hdr_t));

    /* Decrement TTL and check */
    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0) {
        send_icmp_error(sr, pkt, len, 11, (uint8_t)0);
        return; /* Exit if TTL expired */
    }

    /* Recalculate IP checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Find longest prefix match */
    struct sr_rt *route = longest_prefix_match(sr, ip_hdr->ip_dst);
    if (route) {
        struct sr_if* interface = sr_get_interface(sr, route->interface);
        lookup_and_send_packet(sr, route->gw.s_addr, pkt, len, interface);
    } else {
        /*LPM not found, send error type 3 code 0*/
        send_icmp_error(sr, pkt, len, 3, 0);
    }
}

/*--------------------------------------------------------------------- 
 * Searches the routing table for the longest prefix match corresponding
 * to the given destination address.
 *---------------------------------------------------------------------*/
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr) {
  struct sr_rt *walker = sr->routing_table;
  struct sr_rt *longest = 0;
  uint32_t len = 0;
  while (walker) {
    if ((walker->dest.s_addr & walker->mask.s_addr) == (dest_addr & walker->mask.s_addr)) {
      if ((walker->mask.s_addr & dest_addr) > len) {
        len = walker->mask.s_addr & dest_addr;
        longest = walker;
      }
    }
    walker = walker->next;
  }
  return longest;
}

/*--------------------------------------------------------------------- 
 * This method performs an ARP cache lookup for the specified destination 
 * IP address. If an ARP entry is found, it sends the packet. 
 * Otherwise, it queues the packet and initiates an ARP request.
 *---------------------------------------------------------------------*/
void lookup_and_send_packet(struct sr_instance *sr, uint32_t dst_ip, uint8_t *pkt, unsigned int len, struct sr_if *interface) {
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, dst_ip);
  if (entry) {
    memcpy(((sr_ethernet_hdr_t *)pkt)->ether_dhost, entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(((sr_ethernet_hdr_t *)pkt)->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    sr_send_packet(sr, pkt, len, interface->name);
    free(entry);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, dst_ip, pkt, len, interface->name);
    handle_arp_request(sr, req);
  }
}

/*---------------------------------------------------------- 
 * Constructs and sends an ICMP Type 0 (echo reply) packet. 
 *----------------------------------------------------------*/
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *pkt, unsigned int len) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));

  struct sr_rt* lpm = longest_prefix_match(sr, ip_hdr->ip_src);
  if(!lpm) {
    printf("Error: longest prefix match not found.\n");
    return;
  }

  struct sr_if* my_if = sr_get_interface(sr, lpm->interface);

  /* Swap IP addresses to send back*/
  uint32_t temp_ip = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = temp_ip;

  /* set ethernet header source MAC & destination MAC: 00-00-00-00-00-00 */
  memcpy(eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  
  /* Prepare ICMP header */
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

  /* look up arp cache and send packet */ 
  lookup_and_send_packet(sr, lpm->gw.s_addr, pkt, len, my_if);
}


/*--------------------------------------------------------------------- 
 * Constructs and sends an ICMP Type 3 (Destination Unreachable) error 
 * message.
 *---------------------------------------------------------------------*/
void send_icmp_error(struct sr_instance *sr, uint8_t *pkt, unsigned int len, uint8_t type, uint8_t code) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  struct sr_rt* lpm = longest_prefix_match(sr, ip_hdr->ip_src);
  if(!lpm) {
    printf("Error: longest prefix match not found.\n");
    return;
  }

  struct sr_if* my_if = sr_get_interface(sr, lpm->interface);
  
  /* Set up new packet */
  unsigned int ret_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t* ret_pkt = malloc(ret_len);

  /* Set up headers */
  sr_ethernet_hdr_t* ret_eth_hdr = (sr_ethernet_hdr_t*)ret_pkt;
  sr_ip_hdr_t* ret_ip_hdr = (sr_ip_hdr_t*)(ret_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(ret_pkt + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
  
  ret_ip_hdr->ip_v    = 4;
  ret_ip_hdr->ip_hl   = sizeof(sr_ip_hdr_t) / 4;
  ret_ip_hdr->ip_tos  = 0;
  ret_ip_hdr->ip_len  = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ret_ip_hdr->ip_id   = htons(0);
  ret_ip_hdr->ip_off  = htons(IP_DF);
  ret_ip_hdr->ip_ttl  = 255;
  ret_ip_hdr->ip_p    = ip_protocol_icmp;
  ret_ip_hdr->ip_src = (code == 3) ? ip_hdr->ip_dst : my_if->ip;
  ret_ip_hdr->ip_dst = ip_hdr->ip_src;
  ret_ip_hdr->ip_sum = 0;
  ret_ip_hdr->ip_sum = cksum(ret_ip_hdr, sizeof(sr_ip_hdr_t));
  
  memcpy(ret_eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ret_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  ret_eth_hdr->ether_type = htons(ethertype_ip);

  /* Prepare ICMP Type 3 header */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->next_mtu = 0;
  icmp_hdr->unused = 0;
  memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /* look up arp cache and send packet */
  lookup_and_send_packet(sr, lpm->gw.s_addr, ret_pkt, ret_len, my_if);

  free(ret_pkt);
}