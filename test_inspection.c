#include "build_server.h"
#include "inspection.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

#include <pcap.h>

/* We've included the UDP header struct for your ease of customization.
 * For your protocol, you might want to look at netinet/tcp.h for hints
 * on how to deal with single bits or fields that are smaller than a byte
 * in length.
 *
 * Per RFC 768, September, 1981.
 */
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */ // including both header and data
	u_short	uh_sum;			/* datagram checksum */
};

// skip ether header, ip header, udp header or tcp header
char * get_payload(char * packet, int caplen, int * payload_len){
	struct ether_header * ethernet_header = NULL;
	struct ip * ip_header = NULL;
	struct UDP_hdr * udp_header = NULL;
	struct tcphdr * tcp_header = NULL;
	
	if(caplen < sizeof(struct ether_header)){
		fprintf(stderr, "caplen less than ether_header\n");
		return NULL;
	}
	ethernet_header = (struct ether_header *) packet;
	if(ethernet_header->ether_type == ETHERTYPE_IP){

	} else {
		fprintf(stderr, "not ip packet\n");
		return NULL;
	}
	// skip ether header
	packet += sizeof(struct ether_header);
	caplen -= sizeof(struct ether_header);

	if(caplen < sizeof(struct ip)){
		fprintf(stderr, "caplen less than ip header\n");
		return NULL;
	}
	ip_header = (struct ip *) packet;
	int ip_header_length = ip_header->ip_hl * 4;
	if(caplen < ip_header_length){
		fprintf(stderr, "caplen less than ip_header_length\n");
		return NULL;
	}
	// skip over ip header
	packet += ip_header_length;
	caplen -= ip_header_length;

	if(ip->ip_p == IPPROTO_TCP){
		if(caplen < sizeof(struct tcphdr)){
			fprintf(stderr, "caplen less than tcphdr\n");
			return NULL;
		}
		tcp_header = (struct tcphdr *) packet;
		int tcp_header_length = tcp_header->th_off * 4;
		if(caplen < tcp_header_length){
			fprintf(stderr, "caplen less than tcp_header_length\n");
			return NULL;
		}
		packet += tcp_header_length;
		caplen -= tcp_header_length;
		int ip_total_len = ntohs(ipheader->ip_len);
		int len = ip_total_len - ip_header_length - tcp_header_length;
		if(len < caplen){
			*payload_len = len;
		} else {
			*payload_len = caplen;
		}
		return packet;
	} else if(ip->ip_p == IPPROTO_UDP){
		if(caplen < sizeof(struct UDP_hdr)){
			fprintf(stderr, "caplen less than UDP_hdr\n");
			return NULL;
		}
		udp_header = (struct UDP_hdr *) packet;
		unsigned len = ntohs(udp_header->uh_ulen);
		if(len < caplen){
			*payload_len = len - sizeof(struct UDP_hdr);
		} else {
			*payload_len = caplen - sizeof(struct UDP_hdr);
		}
		packet += sizeof(struct UDP_hdr);
		return packet;
	} else {
		fprintf(stderr, "not tcp or udp packet\n");
		return NULL;
	}
}
int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s normalized_rules_file test_file\n", args[0]);
		return 0;
	}

	struct memory_pool pool;
	initialize_memory_pool(&pool);

	struct double_list rules_list;
	struct double_list global_signatures_list;
	rules_list.head = rules_list.tail = NULL;
	global_signatures_list.head = global_signatures_list.tail = NULL;
	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	printf("reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	
	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, &global_signatures_list, key, &pool);
	fprintf(stderr, "after read_rules_from_file\n");
	//print_reversible_sketch(&rs);

	// read file, test inspection
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * pcap;
	const unsigned char * packet;
	struct pcap_pkthdr pcap_packet_header;
	pcap = pcap_open_offline(args[2], errbuf);
	if(pcap == NULL){
		fprintf(stderr, "error opening pcap file %s\n", errbuf);
		return 0;
	}

	struct double_list matched_rules_list;
	matched_rules_list.head = matched_rules_list.tail = NULL;
	while((packet = pcap_next(pcap, &pcap_packet_header)) != NULL){
		char * payload;
		int payload_len;
		payload = get_payload(packet, pcap_packet_header.caplen, &payload_len);
		if(payload){
			// inspect payload
			if(payload_len > TOKEN_SIZE){
				int i;
				for(i = 0;i < payload_len - TOKEN_SIZE + 1;i++){
					struct user_token * ut = get_free_user_token(&pool);
					ut->offset = i;
					AES128_ECB_encrypt(&(payload[i]), key, ut->token);

					// new user token arrived, perform additive inspection
					additive_inspection(ut, rs, pool, &matched_rules_list);
				}
			}
		}
	}
	// this should be called when a file inspection is done, or a connection is tared down
	free_all_user_tokens(&pool);

	if(matched_rules_list.head == NULL){
		printf("no malware found in file %s\n", args[2]);
	} else {
		printf("The following malwares found in file %s\n", args[2]);
		struct double_list_node * node = matched_rules_list.head;
		while(node){
			struct rule * r = (struct rule *) node->ptr;
			printf("%s", r->rule_name);
			node = node->next;
		}
	}
	return 0;
}
