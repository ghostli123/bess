#include <rte_tcp.h>

#include "../module.h"
#include "../utils/histogram.h"

static void
timestamp_process_batch(struct module *m, struct pkt_batch *batch)
{
	gate_idx_t ogates[MAX_PKT_BURST];
	gate_idx_t direction[MAX_PKT_BURST];
        struct ether_hdr *eth;
        struct ipv4_hdr *ip;
	uint16_t ipid;
	for (int i = 0; i < batch->cnt; i++) {
		direction[i] = get_igate();

		//printf("process batch, igate: %d\n", direction[i]);

		eth = (struct ether_hdr *)snb_head_data(batch->pkts[i]);

		//printf("start1 %d, %d\n", eth->ether_type, priv->ether_type_ipv4);

		//printf("start2\n");

		ip = (struct ipv4_hdr *)(eth + 1);
		ipid = ip->packet_id;

		//printf("start3 ipid %d \n", ipid);
		if (direction[i] == 0) {

			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_CLIENT ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);

			ogates[i] = 0;
		}

		else if (direction[i] == 1) {
			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM1B ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);
			//printf("IGATE_VM1B ipid %d clock_t start %LF\n", ipid, (long double)start);
  			ogates[i] = 1;
		}

		else if (direction[i] == 2) {  
			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM2B ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);
			//printf("IGATE_VM2B ipid %d clock_t start %LF\n", ipid, (long double)start);
  			ogates[i] = 2;
		}


		else if (direction[i] == 3) {
			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_SERVER ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);
			//printf("IGATE_SERVER ipid %d clock_t start %LF\n", ipid, (long double)start);
  			ogates[i] = 3;
		}

		else if (direction[i] == 5) {  
			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM1A ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);
			//printf("IGATE_VM1A ipid %d clock_t start %LF\n", ipid, (long double)start);
  			ogates[i] = 5;
		}

		else if (direction[i] == 4) {  
			struct timeval timer_usec;
			long long int timestamp_usec; /* timestamp in microsecond */
			gettimeofday(&timer_usec, NULL);
			timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
						                        (long long int) timer_usec.tv_usec;
			printf("IGATE_VM2A ipid %d, %lld microseconds since epoch\n", ipid, timestamp_usec);
			//printf("IGATE_VM2A ipid %d clock_t start %LF\n", ipid, (long double)start);
  			ogates[i] = 4;
		}
	}
	run_split(m, ogates, batch);
}

static const struct mclass timestamp = {
	.name 		= "Timestamp",
	.help		= 
		"marks current time to packets (paired with Measure module)",
	.num_igates 	= MAX_GATES,
	.num_ogates	= MAX_GATES,
	.process_batch 	= timestamp_process_batch,
};

ADD_MCLASS(timestamp)
