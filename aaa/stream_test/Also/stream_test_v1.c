/*********************************************************
* 当前文件:TCP.STREAM_pcap.c
* 文件作者:牛永旺
* 电子邮箱:2511955991@qq.com
* 编写时间:Tue 09 May 2017 11:14:07 AM CST
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
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)	//得出前4位,再计算这4位的值
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


struct tcp_quintet
{
	char src_ipaddr[12];
	char dst_ipaddr[12];
	char pro_type[12];
	int  src_port;
	int  dst_port;
};

struct tcp_quintet prev_quintet;


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
	
#ifndef QUINTET
#define QUINTET
	memset(&prev_quintet, 0, sizeof(prev_quintet));
	
	//获取源ip地址和目的ip地址
	struct tcp_quintet curr_quintet;
	memset(&curr_quintet, 0, sizeof(curr_quintet));
	memcpy(curr_quintet.src_ipaddr, inet_ntoa(ip->ip_src), strlen(inet_ntoa(ip->ip_src)));
	memcpy(curr_quintet.dst_ipaddr, inet_ntoa(ip->ip_dst), strlen(inet_ntoa(ip->ip_dst)));

	printf("Src Ipaddr is %s\n", curr_quintet.src_ipaddr);
	printf("Dst Ipaddr is %s\n", curr_quintet.dst_ipaddr);
	//获取协议类型(数据部分)
	switch(ip->ip_pro)
	{
		case 0x06: strcpy(curr_quintet.pro_type, "TCP");  break;
		case 0x01: strcpy(curr_quintet.pro_type, "ICMP"); break;
		default: break;
	}
	printf("Pro Type is %s\n", curr_quintet.pro_type);
	//获取源port端口和目的port端口
	curr_quintet.src_port = ntohs(tcp->th_sport);
	curr_quintet.dst_port = ntohs(tcp->th_dport);
	printf("Src Port is %d \n", curr_quintet.src_port);
	printf("Dst Port is %d \n", curr_quintet.dst_port);
	
	if(prev_quintet.src_ipaddr == NULL || 
	   prev_quintet.dst_ipaddr == NULL || 
	   prev_quintet.pro_type == NULL || 
	   prev_quintet.src_port == 0 || 
	   prev_quintet.dst_port == 0)
	{
		prev_quintet = curr_quintet;
	}
	if((strcmp(prev_quintet.src_ipaddr ,curr_quintet.src_ipaddr)  || 
	    strcmp(prev_quintet.src_ipaddr ,curr_quintet.dst_ipaddr)) &&
	   (strcmp(prev_quintet.dst_ipaddr ,curr_quintet.dst_ipaddr)  ||
	    strcmp(prev_quintet.dst_ipaddr ,curr_quintet.src_ipaddr)) && 
	    strcmp(prev_quintet.pro_type ,curr_quintet.pro_type)  &&
	   (prev_quintet.src_port == curr_quintet.src_port  || 
	    prev_quintet.src_port == curr_quintet.dst_port) &&
	   (prev_quintet.dst_port == curr_quintet.dst_port  ||
	    prev_quintet.dst_port == curr_quintet.src_port))
	{
		printf("是一个TCP流！\n");
		memset(&prev_quintet, 0, sizeof(prev_quintet));
		prev_quintet = curr_quintet;
	}
	else
	{
		printf("不是一个TCP流！\n");
	}
#endif
}


int main(int argc, char* argv[])
{
	//打开.pcap文件，返回文件句柄
	char error_buf[128] = {0};
	pcap_t *handle = pcap_open_offline("./TCP.STREAM.pcap", error_buf);

	//处理来自活动捕获，或保存到本地的数据包
	int ret = pcap_loop(handle, -1, loop_callback, NULL);
	if(ret == -1)
	{
		printf("pcap_loop error\n");
		return -1;
	}

	return 0;
}

