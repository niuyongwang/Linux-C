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
#include<math.h>


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
	char src_ipaddr[20];
	char dst_ipaddr[20];
	char pro_type[15];
	int  src_port;
	int  dst_port;
};

struct tcp_quintet prev_quintet;
int updata_len = 0;
int uppack_sum = 0;
int downdata_len = 0;
int downpack_sum = 0;


int test(const struct tcp_quintet curr_quintet)
{
	if( prev_quintet.src_ipaddr == NULL || prev_quintet.dst_ipaddr == NULL || prev_quintet.pro_type == NULL ||
	    prev_quintet.src_port == 0 || prev_quintet.dst_port == 0)
	{
		memcpy(prev_quintet.src_ipaddr ,curr_quintet.src_ipaddr, sizeof(curr_quintet.src_ipaddr));
		memcpy(prev_quintet.dst_ipaddr ,curr_quintet.dst_ipaddr, sizeof(curr_quintet.dst_ipaddr));
		memcpy(prev_quintet.pro_type ,curr_quintet.pro_type, sizeof(curr_quintet.pro_type));
		prev_quintet.src_port = curr_quintet.src_port;
		prev_quintet.dst_port = curr_quintet.dst_port;
	}

	if(strcmp(prev_quintet.src_ipaddr, curr_quintet.src_ipaddr) == 0)
	{
		if(strcmp(prev_quintet.dst_ipaddr, curr_quintet.dst_ipaddr) == 0)
		{
			goto aaa;
		}
		else if(strcmp(prev_quintet.dst_ipaddr, curr_quintet.src_ipaddr) == 0)
		{
			goto aaa;
		}
		else
		{
			return -1;
		}
	}
	else if(strcmp(prev_quintet.src_ipaddr, curr_quintet.dst_ipaddr) == 0)
	{
		if(strcmp(prev_quintet.dst_ipaddr, curr_quintet.src_ipaddr) == 0)
		{
			goto aaa;
		}
		else if(strcmp(prev_quintet.dst_ipaddr, curr_quintet.dst_ipaddr) == 0)
		{
			goto aaa;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

aaa:
	if(strcmp(prev_quintet.pro_type ,curr_quintet.pro_type) == 0)
	{
		if(prev_quintet.src_port == curr_quintet.src_port)
		{
			if(prev_quintet.dst_port == curr_quintet.dst_port)
			{
				goto bbb;
			}
			else if(prev_quintet.dst_port == curr_quintet.src_port)
			{
				goto bbb;
			}
			else
			{
				return -1;
			}
		}
		else if(prev_quintet.src_port == curr_quintet.dst_port)
		{
			if(prev_quintet.dst_port == curr_quintet.dst_port)
			{
				goto bbb;
			}
			else if(prev_quintet.dst_port == curr_quintet.src_port)
			{
				goto bbb;
			}
			else
			{
				return -1;
			}
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

bbb:
	memcpy(prev_quintet.src_ipaddr ,curr_quintet.src_ipaddr, sizeof(curr_quintet.src_ipaddr));
	memcpy(prev_quintet.dst_ipaddr ,curr_quintet.dst_ipaddr, sizeof(curr_quintet.dst_ipaddr));
	memcpy(prev_quintet.pro_type ,curr_quintet.pro_type, sizeof(curr_quintet.pro_type));
	prev_quintet.src_port = curr_quintet.src_port;
	prev_quintet.dst_port = curr_quintet.dst_port;
	//printf("是一个TCP流\n");
	return 0;
}


//处理数据包的回调函数
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//定义结构体
	const struct packet_ethernet *ethernet;  /* The ethernet header [1] */
	const struct packet_ip *ip;              /* The IP header */  
	const struct packet_tcp *tcp;            /* The TCP header */
	char *http;								 /* The Http header */
	//计算结构体大小
	//int size_ethernet = sizeof(struct packet_ethernet);
	//int size_ip = sizeof(struct packet_ip);
	//int size_tcp = sizeof(struct packet_tcp);
	
	//初始化结构体
	ethernet = (struct packet_ethernet *)(packet);
	int size_ethlen = sizeof(struct packet_ethernet);  //求出MAC首部长度
	
	ip = (struct packet_ip *)(packet + size_ethlen);
	int size_iphlen = 0;
	if(ip->ip_hlen < 9)
	{
		size_iphlen = (ip->ip_hlen % 10) * 32 / 8;	//求出IP首部长度
	}
	else
	{
		size_iphlen = (ip->ip_hlen % 10 + 10) * 32 / 8;	//求出IP首部长度
	}

	tcp = (struct packet_tcp *)(packet + size_ethlen + size_iphlen);
	int size_tcphlen = TH_OFF(tcp) * 4;	  //求出TCP首部长度

	http = (char *)(packet + size_ethlen + size_iphlen + size_tcphlen);
	int http_len = 0;	//求出HTTP的长度(如果有)
	if((*http=='G') && (*(http+1)=='E') && (*(http+2)=='T'))
	{
		while(1)
		{
			http_len += 1;
			if((*http=='\r') && (*(http+1)=='\n') && (*(http+2)=='\r') && (*(http+3)=='\n'))
			{
				http_len += 3;
				break;
			}
			http += 1;
		}
		printf("http_len is %d\n", http_len);
	}
	else if((*http=='H') && (*(http+1)=='T') && (*(http+2)=='T') && (*(http+3)=='P'))
	{
		while(1)
		{
			http_len += 1;
			if((*http=='\r') && (*(http+1)=='\n') && (*(http+2)=='\r') && (*(http+3)=='\n'))
			{
				http_len += 3;
				break;
			}
			http += 1;
		}
		printf("http_len is %d\n", http_len);
	}
	

	//获取源ip地址和目的ip地址
	struct tcp_quintet curr_quintet;
	memset(&curr_quintet, 0, sizeof(curr_quintet));
	memcpy(curr_quintet.src_ipaddr, inet_ntoa(ip->ip_src), strlen(inet_ntoa(ip->ip_src)));
	memcpy(curr_quintet.dst_ipaddr, inet_ntoa(ip->ip_dst), strlen(inet_ntoa(ip->ip_dst)));

	//获取协议类型(数据部分)
	switch(ip->ip_pro)
	{
		case 0x06: strcpy(curr_quintet.pro_type, "TCP");  break;
		case 0x01: strcpy(curr_quintet.pro_type, "ICMP"); break;
		default: break;
	}
	//获取源port端口和目的port端口
	curr_quintet.src_port = ntohs(tcp->th_sport);
	curr_quintet.dst_port = ntohs(tcp->th_dport);
	
	//获取TCP五原组
	if(test(curr_quintet) == -1)
	{
		printf("不是一个TCP流\n");
		return;
	}
	printf("Src Ipaddr is %s\n", curr_quintet.src_ipaddr);
	printf("Dst Ipaddr is %s\n", curr_quintet.dst_ipaddr);
	printf("Pro Type is %s\n", curr_quintet.pro_type);
	printf("Src Port is %d\n", curr_quintet.src_port);
	printf("Dst Port is %d\n", curr_quintet.dst_port);

	//上行TCP流
	if(strcmp(curr_quintet.src_ipaddr, "10.10.4.12") == 0)
	{
		if(strcmp(curr_quintet.dst_ipaddr, "10.8.0.200") == 0)
		{
			printf("上行流量\n");
			updata_len += size_iphlen;
			updata_len += size_tcphlen;
			updata_len += http_len;
			//printf("http total len is %d\n", http_len);
			uppack_sum++;
		}
	}

	//下行TCP流
	if(strcmp(curr_quintet.src_ipaddr, "10.8.0.200") == 0)
	{
		if(strcmp(curr_quintet.dst_ipaddr, "10.10.4.12") == 0)
		{
			printf("下行流量\n");
			downdata_len += size_iphlen;
			downdata_len += size_tcphlen;
			downdata_len += (ntohs(ip->ip_len) - size_iphlen - size_tcphlen);
			//printf("total len is %d\n", ntohs(ip->ip_len));
			downpack_sum++;
		}
	}
	printf("-----------------------------------\n");
}


int main(int argc, char* argv[])
{
	memset(&prev_quintet, 0, sizeof(prev_quintet));
	//打开.pcap文件，返回文件句柄
	char error_buf[128] = {0};
	//pcap_t *handle = pcap_open_offline("./TCP.STREAM.pcap", error_buf);
	pcap_t *handle = pcap_open_offline("./a.pcap", error_buf);

	//处理来自活动捕获，或保存到本地的数据包
	int ret = pcap_loop(handle, -1, loop_callback, NULL);
	if(ret == -1)
	{
		printf("pcap_loop error\n");
		return -1;
	}

	printf("updata bytes is %d\n", updata_len);
	printf("uppack count is %d\n", uppack_sum);
	printf("downdata bytes is %d\n", downdata_len);
	printf("downpack count is %d\n", downpack_sum);
	return 0;
}

