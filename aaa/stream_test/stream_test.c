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
struct tcp_quintet curr_quintet;
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


void ip_stream(const struct packet_ip *ip)
{
    //上行TCP流
    if(strcmp(curr_quintet.src_ipaddr, "10.10.4.12") == 0)
    {
        if(strcmp(curr_quintet.dst_ipaddr, "10.8.0.200") == 0)
        {
            printf("上行流量\n");
            updata_len += (ntohs(ip->ip_len));
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
            downdata_len += (ntohs(ip->ip_len));
            //printf("total len is %d\n", ntohs(ip->ip_len));
            downpack_sum++;
        }                                                     
    }
    printf("-----------------------------------\n");
}


void tcp_resolve(const struct packet_tcp *tcp, int size_tcphlen)
{
    //获取源port端口和目的port端口
    curr_quintet.src_port = ntohs(tcp->th_sport);
    curr_quintet.dst_port = ntohs(tcp->th_dport); 
    
    //继续判断下一层
/*  //求出HTTP的长度(如果有)
    int http_len = 0;
    char *http = (char *)((char *)tcp + size_tcphlen);
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
*/    
}


void ip_resolve(const struct packet_ip *ip, int size_iphlen)
{	
    //获取源ip地址和目的ip地址
    memset(&curr_quintet, 0, sizeof(curr_quintet));
    memcpy(curr_quintet.src_ipaddr, inet_ntoa(ip->ip_src), strlen(inet_ntoa(ip->ip_src)));
    memcpy(curr_quintet.dst_ipaddr, inet_ntoa(ip->ip_dst), strlen(inet_ntoa(ip->ip_dst)));

	//判断并获取下层协议类型
	if(ip->ip_pro == 0x06)
	{
        strcpy(curr_quintet.pro_type, "TCP");
        //初始化TCP报文
        const struct packet_tcp *tcp; 
		tcp = (struct packet_tcp *)((char *)ip + size_iphlen);
		//求出报文首部长度
        int size_tcphlen = TH_OFF(tcp) * 4;
        //解析报文数据部分
        tcp_resolve(tcp, size_tcphlen);
	}
	else if(ip->ip_pro == 0x01)
	{
        strcpy(curr_quintet.pro_type, "ICMP");
		//size_icmphlen = TH_OFF(tcp) *4;
	}

    //统计IP层开始的流量
    ip_stream(ip);
}


void mac_resolve(const struct packet_ethernet *ethernet, int size_ethlen)
{
    //判断下一层
    if(ntohs(ethernet->ether_type) == 0x0800)
    {
        //初始化IP报文
        int size_iphlen = 0;
        const struct packet_ip *ip;
        ip = (struct packet_ip *)((char *)ethernet + size_ethlen);
        //求出报文首部长度
        if(ip->ip_hlen < 9)
        {
            size_iphlen = (ip->ip_hlen % 10) * 32 / 8;
        }
        else
        {
            size_iphlen = (ip->ip_hlen % 10 + 10) * 32 / 8;
        }
        //解析报文数据部分
        ip_resolve(ip, size_iphlen);
    }
    else if(ntohs(ethernet->ether_type) == 0x0806)
    {
        //arp_resolve(arp, &size_arphlen);
    }

}

//处理数据包的回调函数
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//定义结构体
	//const struct packet_ethernet *ethernet;  /* The ethernet header [1] */
	//const struct packet_ip *ip;              /* The IP header */  
	//const struct packet_tcp *tcp;            /* The TCP header */
	//计算结构体大小
	//int size_ethernet = sizeof(struct packet_ethernet);
	//int size_ip = sizeof(struct packet_ip);
	//int size_tcp = sizeof(struct packet_tcp);

	//初始化MAC报文
    const struct packet_ethernet *ethernet;
	ethernet = (struct packet_ethernet *)(packet);
	//求出报文首部长度
    int size_ethlen = sizeof(struct packet_ethernet);
    //解析报文数据部分
    mac_resolve(ethernet, size_ethlen);
	
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

}


int main(int argc, char* argv[])
{
	memset(&prev_quintet, 0, sizeof(prev_quintet));
	//打开.pcap文件，返回文件句柄
	char error_buf[128] = {0};
	pcap_t *handle = pcap_open_offline("./test.pcap", error_buf);
	//pcap_t *handle = pcap_open_offline("./a.pcap", error_buf);

	//处理来自活动捕获，或保存到本地的数据包
	int ret = pcap_loop(handle, -1, loop_callback, NULL);
	if(ret == -1)
	{
		printf("pcap_loop error\n");
		return -1;
	}
    printf("*********************************\n");
	printf("updata bytes is %d\n", updata_len);
	printf("uppack count is %d\n", uppack_sum);
	printf("downdata bytes is %d\n", downdata_len);
	printf("downpack count is %d\n", downpack_sum);
	return 0;
}

