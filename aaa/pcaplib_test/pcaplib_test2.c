/*********************************************************
 * 当前文件:pcap.c
 * 文件作者:牛永旺
 * 电子邮箱:2511955991@qq.com
 * 编写时间:Fri 05 May 2017 03:07:44 AM CST
 **********************************************************/
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

#define uint32_t	unsigned int

//#define EXTRACT_32BITS(p) \
		((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
		((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
		((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
		((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))


typedef struct {
	uint32_t	val;
} __attribute__((packed)) unaligned_uint32_t;

static inline uint32_t
EXTRACT_32BITS(const void *p)
{
	return ((uint32_t)ntohl(((const unaligned_uint32_t *)(p))->val));
}


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
		u_char	ip_hlen:4, ip_ver:4;
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
		#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)	//得出前4位,再计算这4位的值
		uint8_t	th_flags;				
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

void ethernet_resolve(const struct packet_ethernet *ethernet)
{
		//获取源mac地址和目的mac地址
		unsigned char *mac_string = NULL;
		mac_string = (unsigned char *)ethernet->ether_shost; 
		printf("Source MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
						*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));    
		mac_string = (unsigned char *)ethernet->ether_dhost;  
		printf("Destination MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
						*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

		//获取协议类型(数据部分)
		unsigned short ethernet_type = ntohs(ethernet->ether_type);
		switch(ethernet_type)
		{
				case 0x0800:printf("Data's Type is IP\n");break;
				case 0x0806:printf("Data's Type is ARP\n");break;
				default:break;
		}
}

void ip_resolve(const struct packet_ip *ip)
{
		//获取报文的版本和头部长度
		if(ip->ip_ver == 0x4)
		{
				printf("IP Version is 4\n");
		}
		if(ip->ip_hlen == 0x5)
		{
				printf("IP Header Length is 20\n");
		}
		//printf("IP Header Length is %d\n", ntohs(ip->ip_hlen));
		//获取报文的总长度
		printf("IP Total Length is %d\n", ntohs(ip->ip_len));

		//获取报文的生命周期TTL
		printf("IP Time to Live is %d\n", ip->ip_ttl);

		//获取源ip地址和目的ip地址
		printf("IP Source Address is %s\n", inet_ntoa(ip->ip_src));
		printf("IP Destination Address is %s\n", inet_ntoa(ip->ip_dst));

		printf("IP Header Checksum is %x\n", ntohs(ip->ip_sum));
		//获取协议类型(数据部分)
		switch(ip->ip_pro)
		{
				case 0x06:printf("IP Data Protocol is TCP\n");break;
				case 0x01:printf("IP Data Protocol is ICMP\n");break;
				default:break;
		}
}

void tcp_resolve(const struct packet_tcp *tcp)
{
		//获取源port端口和目的port端口
		printf("TCP Source PORT is %d \n", ntohs(tcp->th_sport));
		printf("TCP Destination PORT is %d \n", ntohs(tcp->th_dport));

		//获取序列号，确认号，头部长度
		printf("TCP Sequence Number %d\n", EXTRACT_32BITS(&tcp->th_seq));
		printf("TCP Acknowledgment Number %d\n", EXTRACT_32BITS(&tcp->th_ack));
		//printf("TCP Sequence Number is %d\n", htonl(tcp->th_seq));
		//printf("TCP Acknowledgment Number is %d\n", htonl(tcp->th_ack));
		printf("TCP Header Length is %d\n", TH_OFF(tcp) * 4);

		//获取标志位，滑动窗口，效验码
		switch(tcp->th_flags)
		{
				case 0x01:printf("TCP Flags's is FIN\n");break;
				case 0x02:printf("TCP Flags's is SYN\n");break;
				case 0x04:printf("TCP Flags's is RST\n");break;
				case 0x08:printf("TCP Flags's is PUSH\n");break;
				case 0x10:printf("TCP Flags's is ACK\n");break;
				case 0x20:printf("TCP Flags's is URG\n");break;
				case 0x40:printf("TCP Flags's is ECE\n");break;
				case 0x80:printf("TCP Flags's is CWR\n");break;
				default:break;
		}
		printf("TCP Window Size is %d\n", ntohs(tcp->th_win));
		printf("TCP Checksum is %x\n", ntohs(tcp->th_sum));
}


//处理数据包的回调函数
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
		//定义结构体
		const struct packet_ethernet *ethernet;  /* The ethernet header [1] */
		const struct packet_ip *ip;              /* The IP header */  
		const struct packet_tcp *tcp;            /* The TCP header */
		//计算结构体大小
		int size_ethernet = sizeof(struct packet_ethernet);
		int size_ip = sizeof(struct packet_ip);
		int size_tcp = sizeof(struct packet_tcp);
		//初始化结构体
		ethernet = (struct packet_ethernet *)(packet);
		ip = (struct packet_ip *)(packet + size_ethernet);
		tcp = (struct packet_tcp *)(packet + size_ethernet + size_ip);

		//解析结构体
		ethernet_resolve(ethernet);
		ip_resolve(ip);
		tcp_resolve(tcp);
		printf("************************\n");
}


int main(int argc,char* argv[])
{
		//打开.pcap文件，返回文件句柄
		char error_buf[128] = {0};
		pcap_t *handle = pcap_open_offline("./test.pcap", error_buf);

		//设置过滤语句
		//char filter_buf[] = "src 10.10.4.12";
		//将过滤语句编译成过滤器可识别的语句
		struct bpf_program bpf;
		//int ret = pcap_compile(handle, &bpf, filter_buf, 1, 0);	
		int ret = 0;
		if(ret == -1)
		{
				printf("pcap_compile error\n");
				return -1;
		}
/*
		//将过滤器添加到文件句柄中
		ret = pcap_setfilter(handle, &bpf);
		if(ret == -1)
		{
				printf("pcap_setfilter error\n");
				return -1;
		}
*/
		//处理来自活动捕获，或保存到本地的数据包
		ret = pcap_loop(handle, -1, loop_callback, NULL);
		if(ret == -1)
		{
				printf("pcap_loop error\n");
				return -1;
		}

		return 0;
}
