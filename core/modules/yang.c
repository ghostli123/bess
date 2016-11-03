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
#define MAX_MAP_ENTRIES 65536
#define NAT_START_PORT  44001


struct yang_mapping_entry {
	//uint16_t ipid;
	struct snbuf *pkt;
	uint16_t count;
};

struct yang_priv {
	uint32_t ether_type_ipv4;
	struct yang_mapping_entry entry[MAX_MAP_ENTRIES];
	int num_entries;
	//uint32_t removal_index;
	gate_idx_t gates[MAX_RR_GATES];
	int ngates;
	//int current_gate;
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
			 uint16_t ipid)
{
	if (priv->num_entries == 0)
		return;
	priv->entry[ipid].count = 0;
	snb_free(priv->entry[ipid].pkt);
	priv->entry[ipid].pkt = 0;
	priv->num_entries--;

	//printf("going to delete\n");
	//delete
	if (priv->num_entries == 0)
		return;

}



static int add_matching_entry(struct yang_priv *priv,
		     uint16_t ipid,
		     struct snbuf *pkt,
		     uint16_t count)
{
	//printf("entry default count: %d; count intended to set is %d\n", priv->entry[ipid].count, count);
	if (priv->num_entries == MAX_MAP_ENTRIES)
		return -1;

	if (priv->entry[ipid].count > 0) {
		return -1;
	}
	else {
		priv->entry[ipid].count = count;
		priv->entry[ipid].pkt = pkt; 
		priv-> num_entries++;
	}
	//printf("after entry set, the count is %d\n", priv->entry[ipid].count);
	return ipid;
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

		int ind = -1;
		//printf("start3 ipid %d, direction %d \n", ipid, direction[i]);
		if (direction[i] == IGATE_CLIENT) {

			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_CLIENT ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);


			//clock_t start = clock();
			//printf("IGATE_CLIENT ipid %d clock_t start %LF\n", ipid, (long double)start);

			pkt = snb_copy(batch->pkts[i]);
			//if (priv->entry[ipid].count > 0)
			//ind = find_matching_entry(priv, ipid);
			ind = add_matching_entry(priv, ipid, pkt, count);
			if (ind == -1) {
				printf("duplicated ipid\n");
				ogates[i] = OGATE_DROP;
			}
			else {
				ogates[i] = OGATE_MIRROR1;
			}
		}

		else if (direction[i] == IGATE_VM1B) {  
			//clock_t start = clock();
			//printf("IGATE_VM1B ipid %d clock_t start %LF\n", ipid, (long double)start);

			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM1B ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);


			pkt = snb_copy(batch->pkts[i]);
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map

			//if the item exists in the table
			if (priv->entry[ipid].count > 0) {
				entry = &(priv->entry[ipid]);
				//printf("VM1B entry count before minus 1 is: %d, ipid: %d\n", entry->count, ipid);
				entry->count -= 1;

				//printf("VM1B entry count after minus 1: %d, ipid: %d\n", entry->count, ipid);

				if (entry->count == 0) {
					//clock_t start = clock();
					//printf("IGATE_VM1B ipid %d clock_t start %LF\n", ipid, (long double)start);
					delete_entry(priv, ipid);
					ogates[i] = OGATE_SERVER;	
				}
				else {
					snb_free(entry->pkt);
					entry->pkt = pkt;	
					ogates[i] = OGATE_DROP;
				}
			}
			//if the item does NOT exist in the table
		 	else{
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 	}
		}

		else if (direction[i] == IGATE_VM2B) {  
			//clock_t start = clock();
			//printf("IGATE_VM2B ipid %d clock_t start %LF\n", ipid, (long double)start);

			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM2B ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);

			
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map

			if (priv->entry[ipid].count > 0) {			
		 		entry = &(priv->entry[ipid]);
				//printf("VM2B entry count before minus 1 is: %d, ipid: %d\n", entry->count, ipid);
				entry->count -= 1;

				//printf("VM2B entry count after minus 1: %d, ipid: %d\n", entry->count, ipid);

				if ( entry->count == 0 ) {
					//clock_t start = clock();
					//printf("IGATE_VM2B ipid %d clock_t start %LF\n", ipid, (long double)start);
					pkt = snb_copy(entry->pkt);
					snb_free(batch->pkts[i]);
					batch->pkts[i] = pkt;
					//delete entry
					delete_entry(priv, ipid);
					ogates[i] = OGATE_SERVER;
				}
				else {
					ogates[i] = OGATE_DROP;
				}
		 	}
		 	else{
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 	}
		}


		else if (direction[i] == IGATE_SERVER) {
			//clock_t start = clock();
			//printf("IGATE_CLIENT ipid %d clock_t start %LF\n", ipid, (long double)start);

			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_SERVER ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);


			pkt = snb_copy(batch->pkts[i]);
			//if (priv->entry[ipid].count > 0)
			//ind = find_matching_entry(priv, ipid);
			ind = add_matching_entry(priv, ipid, pkt, count);
			if (ind == -1) {
				printf("duplicated ipid\n");
				ogates[i] = OGATE_DROP;
			}
			else {
				ogates[i] = OGATE_MIRROR2;
			}
		}

		else if (direction[i] == IGATE_VM1A) {
			//clock_t start = clock();
			//printf("IGATE_VM1B ipid %d clock_t start %LF\n", ipid, (long double)start);

			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM1A ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);



			pkt = snb_copy(batch->pkts[i]);
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map

			//if the item exists in the table
			if (priv->entry[ipid].count > 0) {
				entry = &(priv->entry[ipid]);
				entry->count -= 1;
				if (entry->count == 0) {
					//clock_t start = clock();
					//printf("IGATE_VM1B ipid %d clock_t start %LF\n", ipid, (long double)start);
					delete_entry(priv, ipid);
					ogates[i] = OGATE_CLIENT;	
				}
				else {
					snb_free(entry->pkt);
					entry->pkt = pkt;	
					ogates[i] = OGATE_DROP;
				}
			}
			//if the item does NOT exist in the table
		 	else{
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
		 	}

		}

		else if (direction[i] == IGATE_VM2A) {
			//clock_t start = clock();
			//printf("IGATE_VM2B ipid %d clock_t start %LF\n", ipid, (long double)start);


			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM2A ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);

			
			//the direction is going out (return packets from VNF)
			//find corresponding entry in table by sequence number
			//update (i.e. xor) packet with corresponding data in the table, (free the memory in batch later)
			//count--
			//if count = 0: replace the packet in batch and destroy the entry; set it as ready for sending out; send out
			// check for an existing entry in priv->map

			if (priv->entry[ipid].count > 0) {			
		 		entry = &(priv->entry[ipid]);
				entry->count -= 1;
				if ( entry->count == 0 ) {
					//clock_t start = clock();
					//printf("IGATE_VM2B ipid %d clock_t start %LF\n", ipid, (long double)start);
					pkt = snb_copy(entry->pkt);
					snb_free(batch->pkts[i]);
					batch->pkts[i] = pkt;
					//delete entry
					delete_entry(priv, ipid);
					ogates[i] = OGATE_CLIENT;
				}
				else {
					ogates[i] = OGATE_DROP;
				}
		 	}
		 	else{
				printf("ENTRY NOT FOUND\n");	
				ogates[i] = OGATE_DROP;
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
