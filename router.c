#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct route_table_entry *rtable; 
int rtable_size;

struct arp_entry *arptable;
int arptable_size;

struct arp_entry *arp_cache;
int arp_cache_size;

queue package_queue;

queue backup_queue;

struct package{
	char *payload;
	size_t len;
};

/*comparator for qsort*/
int comparator(const void *ip1, const void *ip2){
	
	struct route_table_entry *re1 = (struct route_table_entry*) ip1;
	struct route_table_entry *re2 = (struct route_table_entry*) ip2;

	uint32_t prefix1 = re1->prefix;
	uint32_t prefix2 = re2->prefix;
	uint32_t mask1 = re1->mask;
	uint32_t mask2 = re2->mask;

	if(ntohl(prefix1 & mask1) == ntohl(prefix2 & mask2))
		return (mask1 - mask2);
	else
		return (ntohl(prefix1 & mask1) - ntohl(prefix2 & mask2));
}


// struct arp_entry *get_arp_entry(uint32_t ip){
	
// 	for(int i = 0; i < arptable_size; i++){
// 		if(arptable[i].ip == ip)
// 			return &arptable[i];
// 	}
// 	return NULL;
// }

/*searches through the arp table for the ip*/
struct arp_entry *get_arp_cache(uint32_t ip){
	
	for(int i = 0; i < arp_cache_size; i++){
		if(arp_cache[i].ip == ip)
			return &arp_cache[i];
	}
	return NULL;
}

/*binary search through the routing table to find the next hop with the biggest mask*/
struct route_table_entry *bsearch_table(uint32_t daddr){
	
	int sf = rtable_size - 1;
	int in = 0;
	int mid = 0;
	uint32_t mask = 0;
	int index = 0;
	while(sf > in){
		mid = (sf + in) / 2;
		if(ntohl(daddr & rtable[mid].mask) < ntohl(rtable[mid].prefix))
			sf = mid - 1;
		else if(ntohl(daddr & rtable[mid].mask) > ntohl(rtable[mid].prefix))
			in = mid + 1;
		else {
			if(ntohl(rtable[mid].mask) > mask){
				mask = ntohl(rtable[mid].mask);
				index = mid;
				in = mid + 1;
			}
			else
				sf = mid - 1;
		}
		}
	
	if(index > 0)
		return &rtable[index];
	else
		if(ntohl(daddr & rtable[in].mask) == ntohl(rtable[in].prefix))
			return &rtable[in];
		else
			return NULL;
}

/*sends icmp messages*/
void icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int interface){
	
	printf("Entered icmp\n");
	char *buf = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	struct ether_header *eth_hdr_new = malloc(sizeof(struct ether_header));
	eth_hdr_new->ether_type = htons(0x0800);
	memcpy(eth_hdr_new->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr_new->ether_shost, eth_hdr->ether_dhost, 6);

	memcpy(buf, eth_hdr_new, sizeof(struct ether_header));

	struct iphdr *ip_hdr_new = malloc(sizeof(struct iphdr));
	memcpy(ip_hdr_new, ip_hdr, sizeof(struct iphdr));
	ip_hdr_new->daddr = ip_hdr->saddr;
	ip_hdr_new->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr_new->protocol = 1;
	ip_hdr_new->ttl = 64;
	ip_hdr_new->tot_len += 64 + sizeof(struct iphdr);
	memcpy(buf + sizeof(struct ether_header), ip_hdr_new, sizeof(struct iphdr));

	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr)));

	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr + sizeof(struct iphdr), 64);

	send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
}

/*sends arp requests in case the "next route" is not in the arp table*/
void arprequest(struct route_table_entry *next_route, int interface){
	
	char buffer[sizeof(struct ether_header) + sizeof(struct arp_header)];

	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	eth_hdr->ether_type = htons(0x0806);
	get_interface_mac(next_route->interface, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, 0xff, 6);

	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	arp_hdr->htype = htons(0x0001);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(0x0001);
	get_interface_mac(next_route->interface, arp_hdr->sha);
	uint32_t ip ;
	ip = inet_addr(get_interface_ip(next_route->interface));
	arp_hdr->spa = ip;
	
	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa = next_route->next_hop;
	memcpy(buffer, eth_hdr, sizeof(struct ether_header));
	memcpy(buffer + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	send_to_link(next_route->interface, buffer, sizeof(struct ether_header) + sizeof(struct arp_header));
}

/*parses ip packets*/
void ippacket(struct iphdr *ip_packet, struct ether_header *eth_hdr, char* buf, int interface){
	
	uint16_t prev_checksum  = ip_packet->check;
	ip_packet->check = 0;
	ip_packet->check = htons(checksum((uint16_t*)ip_packet, sizeof(struct iphdr)));
	
	uint32_t ip = inet_addr(get_interface_ip(interface));
	struct icmphdr *icmp_hdr = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));			
	printf("Type is %d\n", icmp_hdr->type);
	
	/*if the router is the destination for an echo request it will reply with an echo reply*/
	if(ip_packet->daddr == ip)
	{
		if(ip_packet->protocol == 1){
			printf("Type is %d\n", icmp_hdr->type);
			if(icmp_hdr->type == 8){
				icmp(eth_hdr, ip_packet, 0, interface);
			}
		}
		return;
	}

	/*throw the packet if the checksum is wrong*/
	if(prev_checksum != ip_packet->check)
		return;

	/*throw the packet if the ttl is 0 or 1*/
	if(ip_packet->ttl <= 1){
		icmp(eth_hdr, ip_packet, 11, interface);
		return;
	}		

	
	struct route_table_entry *next_route = bsearch_table(ip_packet->daddr);
	
	/*if there is no route to the destination, send an icmp destination unreachable*/
	if (next_route == NULL) {
		icmp(eth_hdr, ip_packet, 3, interface);
		return;
	}

	uint8_t mac[6];
	get_interface_mac(next_route->interface, mac);	
	// struct arp_entry *next_hop = get_arp_entry(next_route->next_hop);
	// printf("Next hop is %d.%d.%d.%d\n", (next_hop->ip >> 24) & 0xff, (next_hop->ip >> 16) & 0xff, (next_hop->ip >> 8) & 0xff, next_hop->ip & 0xff);
	// DIE(next_hop == NULL, "No arp entry for next hop");

	ip_packet->ttl --;
	ip_packet->check = 0;
	ip_packet->check = htons(checksum((uint16_t*) ip_packet, sizeof(struct iphdr)));
	
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr)));

	struct arp_entry *next_hop = get_arp_cache(next_route->next_hop);
	/*if the next hop is not in the arp table, send an arp request*/
	if(next_hop == NULL)
		{
			struct package *package = malloc(sizeof(struct package));
			package->payload = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct route_table_entry));
			memcpy(package->payload, eth_hdr, sizeof(struct ether_header));
			memcpy(package->payload + sizeof(struct ether_header), ip_packet, sizeof(struct iphdr));
			memcpy(package->payload + sizeof(struct ether_header) + sizeof(struct iphdr), next_route, sizeof(struct route_table_entry));
			package->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct route_table_entry);
			queue_enq(package_queue, package);
			arprequest(next_route, interface);
			return;
		}
	/*if the next hop is in the arp table, forward the packet*/
	else
	{
		memcpy(eth_hdr->ether_dhost, next_hop->mac, 6);
		get_interface_mac(next_route->interface, eth_hdr->ether_shost);
		// printf("Sending packet to %d", ip_packet->daddr);
		eth_hdr->ether_type = htons(0x0800);
		// char *buf = malloc(sizeof(struct ether_header) + sizeof(struct iphdr));
		// memcpy(buf, eth_hdr, sizeof(struct ether_header));
		// memcpy(buf + sizeof(struct ether_header), ip_packet, sizeof(struct iphdr));
		if(icmp_hdr != NULL)
			send_to_link(next_route->interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
		else
			send_to_link(next_route->interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr));
	}
}

/*parses arp packets*/
void arppacket(struct arp_header *arp_packet, struct ether_header *eth_hdr, int interface){
	
	/*if the arp packet is an arp request, send an arp reply*/
	if(ntohs(arp_packet->op) == 1){
		struct arp_header *arp_reply = malloc(sizeof(struct arp_header));
		arp_reply->htype = htons(0x0001);
		arp_reply->ptype = htons(0x0800);
		arp_reply->hlen = 6;
		arp_reply->plen = 4;
		arp_reply->op = htons(0x0002);
		arp_reply->spa = arp_packet->tpa;
		memcpy(arp_reply->tha, arp_packet->sha, 6);
		arp_reply->tpa = arp_packet->spa;
		get_interface_mac(interface, arp_reply->sha);

		struct ether_header *eth_reply = malloc(sizeof(struct ether_header));
		eth_reply->ether_type = htons(0x0806);
		memcpy(eth_reply->ether_dhost, arp_packet->sha, 6);
		get_interface_mac(interface, eth_reply->ether_shost);

		char buf[sizeof(struct ether_header) + sizeof(struct arp_header)];
		memcpy(buf, eth_reply, sizeof(struct ether_header));
		memcpy(buf + sizeof(struct ether_header), arp_reply, sizeof(struct arp_header));
		send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
	}
	/*if the arp packet is an arp reply, add the entry to the arp table*/
	else if(ntohs(arp_packet->op) == 2){
		
		struct arp_entry *arp_entry = malloc(sizeof(struct arp_entry));
		arp_entry->ip = arp_packet->spa;
		memcpy(arp_entry->mac, arp_packet->sha, 6);
		memcpy(&arp_cache[arp_cache_size], arp_entry, sizeof(struct arp_entry));
		arp_cache_size++;
		/*if there are packets waiting for this arp reply, send them*/
		while(!queue_empty(package_queue)){
			struct package *package = queue_deq(package_queue);
			struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
			memcpy(eth_hdr, package->payload, sizeof(struct ether_header));
			struct iphdr *ip_packet = malloc(sizeof(struct iphdr));
			memcpy(ip_packet, package->payload + sizeof(struct ether_header), sizeof(struct iphdr));
			struct route_table_entry *next_route = malloc(sizeof(struct route_table_entry));
			memcpy(next_route, package->payload + sizeof(struct ether_header) + sizeof(struct iphdr), sizeof(struct route_table_entry));
			struct arp_entry *next_hop = get_arp_cache(next_route->next_hop);
			/*if we didn't receive a reply for "next_hop" yet, put the packet back in the queue*/
			if(next_hop == NULL){
				queue_enq(backup_queue, package);
				continue;
			}
			eth_hdr->ether_type = htons(0x0800);
			memcpy(eth_hdr->ether_dhost, next_hop->mac, 6);
			char *buf = malloc(sizeof(struct ether_header) + sizeof(struct iphdr));
			memcpy(buf, eth_hdr, sizeof(struct ether_header));
			memcpy(buf + sizeof(struct ether_header), ip_packet, sizeof(struct iphdr));
			ip_packet->ttl --;
			ip_packet->check = 0;
			ip_packet->check = htons(checksum((void*) ip_packet, sizeof(struct iphdr)));
			// get_interface_mac(interface, eth_hdr->ether_shost);

			send_to_link(next_route->interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr));
		
		}
		/*swap the queues*/
		queue aux = package_queue;
		package_queue = backup_queue;
		backup_queue = aux;
	}
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];
	
	// Do not modify this line
	init(argc - 2, argv + 2);
	rtable = malloc(100000 * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);
	qsort((void*) rtable, rtable_size, sizeof(struct route_table_entry), comparator);
	package_queue = queue_create();
	backup_queue = queue_create();
	// arptable = malloc(100000 * sizeof(struct arp_entry));
	// arptable_size = parse_arp_table("arp_table.txt", arptable);

	arp_cache = malloc(100000 * sizeof(struct arp_entry));
	arp_cache_size = 0;
	
	while (1) {

		int interface;
		size_t len;
		printf("Waiting for packet\n");
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("Received packet from interface %d\n", interface);
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/*if the packet is an ip packet, send it to the ippacket function*/
		if( ntohs(eth_hdr->ether_type) == 0x0800 ){
			struct iphdr *ip_packet = (struct iphdr*) (buf + sizeof(struct ether_header));
			printf("A intrat pe aici(ip).\n");
			ippacket(ip_packet, eth_hdr, buf, interface);			
			printf("Received ip packet from ip address %d.%d.%d.%d\n", (ip_packet->saddr >> 24) & 0xff, (ip_packet->saddr >> 16) & 0xff, (ip_packet->saddr >> 8) & 0xff, ip_packet->saddr & 0xff);
		}
		/*if the packet is an arp packet, send it to the arppacket function*/
		else if( ntohs(eth_hdr->ether_type) == 0x0806 ){
			struct arp_header *arp_packet = (struct arp_header*) (buf + sizeof(struct ether_header));
			arppacket(arp_packet, eth_hdr, interface);

		}
	}
}

