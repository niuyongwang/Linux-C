#ifndef __HEADER__
#define __HEADER__
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<pcap/pcap.h>
#include<time.h>
#include<netinet/in.h>
#include<sys/types.h>  
#include<sys/socket.h>
#include<ctype.h>
#include<sys/mman.h>
#include<fcntl.h>
#endif

/* MAC头 */
struct packet_ethernet
{  
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */  
	u_short ether_type;                     /* IP? ARP? RARP? etc */  
};

/* IP头 */
struct packet_ip 
{
	#if BYTE_ORDER == BIG_ENDIAN
	u_char  ip_ver:4, ip_hlen:4;    /* version << 4 | header length >> 2 */
	#endif
	#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	ip_hlen:4, ip_ver:4;	/* version << 4 | header length >> 2 */
	#endif
	u_char  ip_tos;                 /* type of service */  
	u_short ip_len;                 /* total length */  
	u_short ip_id;                  /* identification */  
	u_short ip_off;                 /* fragment offset field */  
	#define IP_RF 0x8000            /* reserved fragment flag */  
	#define IP_DF 0x4000            /* dont fragment flag */  
	#define IP_MF 0x2000            /* more fragments flag */  
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */  
	u_char  ip_ttl;                 /* time to live */  
	u_char  ip_pro;                 /* protocol */  
	u_short ip_sum;                 /* checksum */  
	struct  in_addr ip_src;  		/* source and src address */  
	struct  in_addr ip_dst;       	/* source and dest address */  
};

/* TCP头 */
struct packet_tcp 
{  
	u_short th_sport;               /* source port */  
	u_short th_dport;               /* destination port */  
	uint32_t  th_seq;               /* sequence number */  
	uint32_t  th_ack;               /* acknowledgement number */
	uint8_t th_offx2;   			/* data offset, rsvd */  
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)	//计算出前4位,将其移到后4位的位置,再计算这后4位的值
	uint8_t	th_flags;				/* flags */
	#define TH_FIN  	0x01
	#define TH_SYN  	0x02
	#define TH_RST  	0x04
	#define TH_PUSH 	0x08
	#define TH_ACK  	0x10
	#define TH_URG  	0x20
	#define TH_ECE  	0x40
	#define TH_CWR  	0x80
	#define TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)  
	u_short th_win;                 /* window */  
	u_short th_sum;                 /* checksum */  
	u_short th_urp;                 /* urgent pointer */  
}; 

/* UDP头 */
struct packet_udp
{
	u_short th_sport;               /* source port */  
	u_short th_dport;               /* destination port */
	u_short th_len;					/* length */
	u_short th_sum;                 /* checksum */
};


//统计字段(单个数据包)
struct stream_log
{
	char src_ipaddr[20];
	char dst_ipaddr[20];
	char pro_type[15];
	int  src_port;
	int  dst_port;
    int  updata_len;
    int  uppack_sum;
    int  downdata_len;
    int  downpack_sum;
    struct stream_log *next;
};

//哈希表存储(单个TCP流)
struct hash_table
{
    struct stream_log *stream[500];
};

struct hash_table *stream_hash;



int write_stream(FILE *fp, struct hash_table *stream_hash);
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int compare_stream(const struct stream_log *stream_tmp, const struct stream_log *stream_data);

void udp_resolve(const struct packet_udp *udp, int size_udphlen, struct stream_log *stream_data);
void tcp_resolve(const struct packet_tcp *tcp, int size_tcphlen, struct stream_log *stream_data);
void ip_resolve(const struct packet_ip *ip, int size_iphlen, struct stream_log *stream_data);
void mac_resolve(const struct packet_ethernet *ethernet, int size_ethlen, struct stream_log *stream_data);
void get_stream(const u_char *packet, struct stream_log *stream_data);

int find_hash_table(const struct hash_table *stream_hash, const struct stream_log *stream_data);
int instert_hash_table(struct hash_table *stream_hash, const struct stream_log *stream_data);
int update_hash_table(struct stream_log *stream_key, const struct stream_log *stream_data);


