#include "../module.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <arpa/inet.h>

#define MAX_RR_GATES	16384

//igate
#define IGATE_CLIENT    0
#define IGATE_VM1B	1  
#define IGATE_VM2B	2
#define IGATE_SERVER    3
#define IGATE_VM1A	4  
#define IGATE_VM2A	5

//ogate
#define OGATE_MIRROR1	    0
#define OGATE_DROP	    1
#define OGATE_SERVER	    2
#define OGATE_MIRROR2	    3
#define OGATE_CLIENT	    4

#define PARALLEL_OGATE 0
#define SERIAL_OGATE 1

#define PROTO_TYPE_ICMP 0x01
#define PROTO_TYPE_TCP  0x06
#define PROTO_TYPE_UDP  0x11
#define OUTBOUND 0
#define INBOUND  1
#define MAX_MAP_ENTRIES 99999
#define NAT_START_PORT  44001

struct l2_table
{
        struct l2_entry *table;
        uint64_t size;
        uint64_t size_power;
        uint64_t bucket;
        uint64_t count;
};

static void log_info_ip(uint32_t ip)
{
	char buf[16];
	const char* result=inet_ntop(AF_INET,&ip,buf,sizeof(buf));
	if (result==0) {
	  log_info("failed to convert address to string (errno=%d)",errno);
	}
	log_info("%s", buf);
}


struct yang_mapping_entry {
	/*uint32_t in_ip;
	uint32_t out_ip;
	uint16_t in_port;
	uint16_t out_port;
	uint16_t nat_port;*/
	uint16_t ipid;
	struct snbuf *pkt;
	uint16_t count;
};

struct yang_priv {
	//uint32_t nat_ip;
	uint32_t ether_type_ipv4;
	struct yang_mapping_entry entry[MAX_MAP_ENTRIES];
	int num_entries;

	gate_idx_t gates[MAX_RR_GATES];
	int ngates;
	int current_gate;
	int per_packet;
};

static struct snobj *
command_set_mode(struct module *m, const char *cmd, struct snobj *arg)
{
	struct yang_priv *priv = get_priv(m);

	const char *mode = snobj_str_get(arg);

	if (!mode)
		return snobj_err(EINVAL, "argument must be a string");

	if (strcmp(mode, "packet") == 0)
		priv->per_packet = 1;
	else if (strcmp(mode, "batch") == 0)
		priv->per_packet = 0;
	else
		return snobj_err(EINVAL,
				"argument must be either 'packet' or 'batch'");

	return NULL;
}

static struct snobj *
command_set_gates(struct module *m, const char *cmd, struct snobj *arg)
{
	struct yang_priv *priv = get_priv(m);

	if (snobj_type(arg) == TYPE_INT) {
		int gates = snobj_int_get(arg);

		if (gates < 0 || gates > MAX_RR_GATES || gates > MAX_GATES)
			return snobj_err(EINVAL, "no more than %d gates",
					MIN(MAX_RR_GATES, MAX_GATES));

		priv->ngates = gates;
		for (int i = 0; i < gates; i++)
			priv->gates[i] = i;

	} else if (snobj_type(arg) == TYPE_LIST) {
		struct snobj *gates = arg;

		if (gates->size > MAX_RR_GATES)
			return snobj_err(EINVAL, "no more than %d gates",
					MAX_RR_GATES);

		for (int i = 0; i < gates->size; i++) {
			struct snobj *elem = snobj_list_get(gates, i);

			if (snobj_type(elem) != TYPE_INT)
				return snobj_err(EINVAL,
						"'gate' must be an integer");

			priv->gates[i] = snobj_int_get(elem);
			if (!is_valid_gate(priv->gates[i]))
				return snobj_err(EINVAL, "invalid gate %d",
						priv->gates[i]);
		}

		priv->ngates = gates->size;

	} else
		return snobj_err(EINVAL, "argument must specify a gate "
				"or a list of gates");

	return NULL;
}

static void delete_entry(struct yang_priv *priv,
			 int index)
{
	printf("going to delete\n");
	//delete
	if (priv->num_entries == 0)
		return;
	printf("del_entry: index %d\n", index);
  
	/*priv->entry[priv->num_entries].in_ip    = in_ip;
	priv->entry[priv->num_entries].out_ip   = out_ip;
	priv->entry[priv->num_entries].in_port  = in_port;
	priv->entry[priv->num_entries].out_port = out_port;
	priv->entry[priv->num_entries].nat_port = htons(NAT_START_PORT +
							priv->num_entries);*/
	priv->entry[index].ipid = 0;
	priv->entry[index].count = 0;
	snb_free(priv->entry[index].pkt);
	priv->entry[index].pkt = 0;
	
	//priv->num_entries--;
	//return priv->num_entries - 1;
}

static int add_entry(struct yang_priv *priv,
		     uint16_t ipid,
		     struct snbuf *pkt,
		     uint16_t count)
		     //uint32_t in_ip,
		     //uint16_t in_port,
		     //uint32_t out_ip,
		     //uint16_t out_port)
{
	if (priv->num_entries == MAX_MAP_ENTRIES)
		return -1;
	//printf("add_entry: ipid %d\n", ipid);
  
	/*priv->entry[priv->num_entries].in_ip    = in_ip;
	priv->entry[priv->num_entries].out_ip   = out_ip;
	priv->entry[priv->num_entries].in_port  = in_port;
	priv->entry[priv->num_entries].out_port = out_port;
	priv->entry[priv->num_entries].nat_port = htons(NAT_START_PORT +
							priv->num_entries);*/
	priv->entry[priv->num_entries].ipid = ipid;
	priv->entry[priv->num_entries].count = count;
	priv->entry[priv->num_entries].pkt = pkt;
	
	priv->num_entries++;
	return priv->num_entries - 1;
}


static int outbound_flow_match(struct yang_mapping_entry *entry,
			       /*struct ipv4_hdr *ip,
			       uint16_t *src_port,
			       uint16_t *dst_port)*/
			       uint16_t ipid)
{
	/*return ( ip->src_addr == entry->in_ip   &&
		 *src_port    == entry->in_port &&
		 ip->dst_addr == entry->out_ip  &&
		 *dst_port    == entry->out_port );*/
	return ( ipid == entry->ipid );
}


static int inbound_flow_match(//struct yang_priv *priv,
			      struct yang_mapping_entry *entry,
			      /*struct ipv4_hdr *ip,
			      uint16_t *src_port,
			      uint16_t *dst_port)*/
			      uint16_t ipid)
{
	/*return ( ip->dst_addr == priv->nat_ip &&
		 *dst_port    == entry->nat_port &&
		 ip->src_addr == entry->out_ip &&
		 *src_port    == entry->out_port );*/
	return ( ipid == entry->ipid );
}


static int find_matching_entry(struct yang_priv *priv,
			       gate_idx_t direction,
			       uint16_t ipid)
			       //struct ipv4_hdr *ip,
			       //uint16_t *src_port,
			       //uint16_t *dst_port)
{
	struct yang_mapping_entry *entry;
	for(int i=0; i<priv->num_entries; i++) {
		entry = &(priv->entry[i]);
		//printf("direction %d", direction);
		if (direction == IGATE_CLIENT) {
		  if (outbound_flow_match(entry,
					  ipid
					  //src_port,
					  //dst_port))
					  ))
		    return i;
		}
		else if (direction == IGATE_VM1B || direction == IGATE_VM2B) {
		  if (inbound_flow_match(//priv,
					 entry,
					 ipid
					 //src_port,
					 //dst_port))
					 ))
		    return i;
		}
		else if (direction == IGATE_SERVER) {
		  if (outbound_flow_match(entry,
					  ipid
					  //src_port,
					  //dst_port))
					  ))
		    return i;
		}
		else if (direction == IGATE_VM1A || direction == IGATE_VM2A) {
		  if (inbound_flow_match(//priv,
					 entry,
					 ipid
					 //src_port,
					 //dst_port))
					 ))
		    return i;
		}
		else
		  return -1;
	}
	return -1;
}


static struct snobj *yang_init(struct module *m,
			       struct snobj *arg)
{
	log_info("YANG:yang_init\n");
	printf("yang:init\n");
	struct yang_priv *priv = get_priv(m);
	priv->ether_type_ipv4 = htons(ETHER_TYPE_IPv4);

	// Set the nat ip based on the input arg
	//	if (arg) {
	//  char *ip_str = snobj_eval_str(arg, "ip");
	//  char *octet;
	//  char *left;
	//  octet = strtok(ip_str,".");
	
	// hardcode the nat IP
	//priv->nat_ip = htonl(IPv4(192, 168, 10, 4));
		  
	return NULL;
}


static void yang_process_batch(struct module *m,
			       struct pkt_batch *batch)
{
	gate_idx_t ogates[MAX_PKT_BURST];
	gate_idx_t direction[MAX_PKT_BURST];
        struct ether_hdr *eth;
        struct ipv4_hdr *ip;
        //void *l4;
        //uint16_t *l4_cksum;
        //uint16_t *src_port;
        //uint16_t *dst_port;
        struct yang_priv *priv = get_priv(m);
        struct yang_mapping_entry *entry;
	uint16_t ipid;
	uint16_t count = 2;
	struct snbuf *pkt; 
	for (int i = 0; i < batch->cnt; i++) {
		direction[i] = get_igate();

		//printf("process batch, igate: %d\n", direction[i]);

		eth = (struct ether_hdr *)snb_head_data(batch->pkts[i]);

		//printf("start1 %d, %d\n", eth->ether_type, priv->ether_type_ipv4);

		//printf("start2\n");

		ip = (struct ipv4_hdr *)(eth + 1);
		ipid = ip->packet_id;
		pkt = snb_copy(batch->pkts[i]);
		
		int ind = -1;
		printf("start3 ipid %d \n", ipid);
		if (direction[i] == IGATE_CLIENT) {
			//if the direction is going to VNF
			//add sequence number into table as tag 
			//add batch->pkts[i] to table as data
			//add the number of distributed vnf to table as count
			// check for an existing entry
		  	ind = find_matching_entry(priv,
					    	  direction[i],
					    	  ipid);

			printf("process batch, index: %d\n", ind);
			// add entry if none exists
			if (ind < 0)
			{
				ind = add_entry(priv,
					    	ipid,
						pkt,
						count);
				ogates[i] = OGATE_MIRROR1;
			}
			else {
				printf("duplicated ipid\n");
				ogates[i] = OGATE_DROP;
				//continue;
			}
		}

		else if (direction[i] == IGATE_VM1B) {  
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map
		  	ind = find_matching_entry(priv,
					    direction[i],
					    ipid);	
			
			// if one exists, rewrite destination ip/port
		 	if (ind >= 0) {
		 		entry = &(priv->entry[ind]);
				entry->count -= 1;
				if ( entry->count == 0 ) {
					//delete entry
					delete_entry(priv, ind);
					ogates[i] = OGATE_SERVER;	
				}
				else {
					ogates[i] = OGATE_DROP;
				}
		 	}
		 	else{
		 		// packet should be deleted
		 		//log_info("ENTRY NOT FOUND\n");
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 		//continue;
		 	}
		}

		else if (direction[i] == IGATE_VM2B) {  
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map
		  	ind = find_matching_entry(priv,
					    direction[i],
					    ipid);	
			
			// if one exists, rewrite destination ip/port
		 	if (ind >= 0) {
		 		entry = &(priv->entry[ind]);
				entry->count -= 1;
				if ( entry->count == 0 ) {
					//delete entry
					delete_entry(priv, ind);
					ogates[i] = OGATE_SERVER;						
				}
				else {
					ogates[i] = OGATE_DROP;
				}
		 	}
		 	else{
		 		// packet should be deleted
		 		//log_info("ENTRY NOT FOUND\n");
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 		//continue;
		 	}
		}


		else if (direction[i] == IGATE_SERVER) {
			//if the direction is going to VNF
			//add sequence number into table as tag 
			//add batch->pkts[i] to table as data
			//add the number of distributed vnf to table as count
			// check for an existing entry
		  	ind = find_matching_entry(priv,
					    	  direction[i],
					    	  ipid);

			printf("process batch, index: %d\n", ind);
			// add entry if none exists
			if (ind < 0)
			{
				ind = add_entry(priv,
					    	ipid,
						pkt,
						count);
				ogates[i] = OGATE_MIRROR2;
			}
			else {
				printf("duplicated ipid\n");
				ogates[i] = OGATE_DROP;
				//continue;
			}
		}

		else if (direction[i] == IGATE_VM1A) {  
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map
		  	ind = find_matching_entry(priv,
					    direction[i],
					    ipid);	
			
			// if one exists, rewrite destination ip/port
		 	if (ind >= 0) {
		 		entry = &(priv->entry[ind]);
				entry->count -= 1;
				if ( entry->count == 0 ) {
					//delete entry
					delete_entry(priv, ind);
					ogates[i] = OGATE_CLIENT;	
				}
				else {
					ogates[i] = OGATE_DROP;
				}
		 	}
		 	else{
		 		// packet should be deleted
		 		//log_info("ENTRY NOT FOUND\n");
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 		//continue;
		 	}
		}

		else if (direction[i] == IGATE_VM2A) {  
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map
		  	ind = find_matching_entry(priv,
					    direction[i],
					    ipid);	
			
			// if one exists, rewrite destination ip/port
		 	if (ind >= 0) {
		 		entry = &(priv->entry[ind]);
				entry->count -= 1;
				if ( entry->count == 0 ) {
					//delete entry
					delete_entry(priv, ind);
					ogates[i] = OGATE_CLIENT;						
				}
				else {
					ogates[i] = OGATE_DROP;
				}
		 	}
		 	else{
		 		// packet should be deleted
		 		//log_info("ENTRY NOT FOUND\n");
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 		//continue;
		 	}
		}

		else {
			printf("WRONG IGATE\n");
			ogates[i] = OGATE_DROP;
			//continue;
		}
	}
	run_split(m, ogates, batch);
	//run_next_module(m, batch);
	
}

static const struct mclass yang = {
	.name 			= "YANG",
	.help			= "parallel",
	.def_module_name	= "YANG",
	.num_igates		= MAX_GATES,
	.num_ogates		= MAX_GATES,
	.priv_size	        = sizeof(struct yang_priv),
	.init 		        = yang_init,
	.process_batch 		= yang_process_batch,
};

ADD_MCLASS(yang)
