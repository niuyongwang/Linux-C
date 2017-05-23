#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <time.h>

/* MAC数据帧头部 */
struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* 目的主机的地址 */
	u_char ether_shost[ETHER_ADDR_LEN]; /* 源主机的地址 */
	u_short ether_type; /* IPv4 */
};

/* ARP报文头部 */
struct sniff_arp
{
	u_short arp_hd_type;	/* 物理类型 */
	u_char arp_pro_type;	/* 协议类型 */
	u_char arp_hd_size;		/* 物理大小 */
	u_char arp_pro_size;	/* 协议大小 */
	u_short arp_opcode;		/* 操作码*/
	u_char arp_send_mac[ETHER_ADDR_LEN];/* 发送端mac地址 */
	struct in_addr arp_send_ip;			/* 发送端ip地址 */
	u_char arp_targ_mac[ETHER_ADDR_LEN];/* 接收目标mac地址 */
	struct in_addr arp_targ_ip;			/* 接收目标ip地址*/
};

/* IP数据包的头部 */
struct sniff_ip
{
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int ip_hl:4, /* 头部长度 */
	ip_ver:4; 	   /* 版本号 */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int ip_v:4, /* 版本号 */
	ip_hl:4; 	  /* 头部长度 */
#endif
	u_char  ip_tos; /* 服务类型 */
	u_short ip_len; /* 总长度 */
	u_short ip_ide; /* 标志号 */
	u_short ip_off; /* 碎片偏移 */
	u_char  ip_ttl; /* 生存时间 */
	u_char  ip_pro; /* 协议类型 */
	u_short ip_sum; /* 校验和 */
	struct in_addr ip_src; /* 源地址 */
	struct in_addr ip_dst; /* 目的地址 */
};

/* TCP数据包的头部 */
struct sniff_tcp
{
	u_short th_sport; /* 源端口 */
	u_short th_dport; /* 目的端口 */
	u_int th_seq;	  /* 包序号 */
	u_int th_ack;     /* 确认序号 */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int th_x2:4,    /* 还没有用到 */
	th_off:4; 	      /* 数据偏移 */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int th_off:4,   /* 数据偏移 */
	th_x2:4; 	      /* 还没有用到 */
#endif
	u_char  th_flags;/* 标志位 */
	u_short th_win;  /* 滑动窗口 */
	u_short th_sum;  /* 校验和 */
	u_short th_urp;  /* 紧急位 */
};


/* ICMP数据包的头部 */
struct sniff_icmp
{
	u_char icmp_type;
	u_char icmp_code;
	u_short icmp_sum;
	u_char icmp_iden;
	u_char icmp_seq_num;
};


void ethernet_icmp(const struct sniff_icmp *icmp)
{
	printf("------------ICMP-----------\n");

	//剥离完IP层的数据包，下一个继续剥离ICMP的数据包
	if(icmp->icmp_type == 0x08)
	{
		printf("ICMP Type is ping's request\n");
		printf("ICMP Checksum is %d\n", icmp->icmp_sum);
	}
	else if(icmp->icmp_type == 0x00)
	{
		printf("ICMP Type is ping's reply\n");
		printf("ICMP Checksum is %d\n", icmp->icmp_sum);
	}
	printf("ICMP Identifier is %d\n", icmp->icmp_iden);
	printf("ICMP Sequence number is %d\n", icmp->icmp_seq_num);
}

void ethernet_tcp(const struct sniff_tcp *tcp)
{
	printf("------------TCP-----------\n");

    //剥离完IP层的数据包，下一个继续剥离TCP层的数据报文
	printf("TCP Sequence Number %d\n", tcp->th_seq);
	printf("TCP Acknowledgment Number %d\n", tcp->th_ack);
	printf("TCP Window Size Value %d\n", tcp->th_win);
	printf("TCP Checksum %d\n", tcp->th_sum);


	//获取源port端口和目的port端口
	printf("Source PORT is %d \n", tcp->th_sport);
	printf("Destination PORT is %d \n", tcp->th_dport);
}

void ethernet_arp(const struct sniff_arp *arp)
{
	printf("------------ARP-----------\n");

	//剥离ARP报文首部
	if(arp->arp_hd_type == 1)
	{
		printf("ARP Hardware type is Ethernet\n");
	}
	if(arp->arp_pro_type == 0x0800)
	{
		printf("ARP Protocol type is IPv4\n");
	}
	printf("ARP Hardware Size is %d\n", arp->arp_hd_size);
	printf("ARP Protocol Size is %d\n", arp->arp_pro_size);

    unsigned char *mac_string = NULL;
    mac_string = (unsigned char *)arp->arp_send_mac; 
    printf("Sender MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
            *(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));    
    mac_string = (unsigned char *)arp->arp_targ_mac;  
    printf("Target MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
            *(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5)); 

	printf("Sender IP Address is %s \n", inet_ntoa(arp->arp_send_ip));
	printf("Target IP Address is %s \n", inet_ntoa(arp->arp_targ_ip));

}

void ethernet_ip(const struct sniff_ip *ip, const struct sniff_tcp *tcp, const struct sniff_icmp *icmp)
{
	printf("------------IP-----------\n");
    
	//剥离完MAC层的以太网帧，下一个继续剥离IP层的数据包
	if(ip->ip_ver == 0x4)
	{
		printf("IP Version is 4\n");
	}
	if(ip->ip_hl == 0x5)
	{
		printf("IP Header Length is 20 bytes\n");
	}
	printf("IP Total Length is %d\n", ip->ip_len);

	//获取源ip地址和目的ip地址
	printf("Source IP Address is %s \n", inet_ntoa(ip->ip_src));
	printf("Destination IP Address is %s \n", inet_ntoa(ip->ip_dst));

	//获取协议类型(数据部分)
    switch(ip->ip_pro)
    {
        case 0x06:printf("Data's Protocol is TCP\n");ethernet_tcp(tcp);break;
        case 0x01:printf("Data's Protocol is ICMP\n");ethernet_icmp(icmp);break;
        default:break;
    }
}

//第二个参数是数据包的首部，第三个参数是数据包的数据部
void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *pcap_packet)
{
	printf("------------MAC-----------\n");
	
	//剥离以太网帧的首部
    printf("Packet Lenght is %d\n", packet_header->len); // 真正抓到的数据包的长度
    printf("Packet Tiemout is %s\n", ctime((time_t *)&(packet_header->ts.tv_sec))); //真正抓到的数据包的时间

	/*给各层协议定义结构体指针*/
	const struct sniff_ethernet *ethernet; /* 以太网帧头部*/
	const struct sniff_arp *arp;		   /* ARP包头部*/
	const struct sniff_ip *ip; 	 		   /* IP包头部 */
	const struct sniff_tcp *tcp; 		   /* TCP包头部 */
	const struct sniff_icmp *icmp;
	/*计算每个结构体中的变量大小*/
	int size_ethernet = sizeof(struct sniff_ethernet);
	int size_arp = sizeof(struct sniff_arp);
	int size_ip = sizeof(struct sniff_ip);
	int size_tcp = sizeof(struct sniff_tcp);
	int size_icmp = sizeof(struct sniff_icmp);
	/*初始化每个结构体*/
	ethernet = (struct sniff_ethernet*)(pcap_packet);
	arp = (struct sniff_arp*)(pcap_packet + size_ethernet);
	ip = (struct sniff_ip*)(pcap_packet + size_ethernet);
	tcp = (struct sniff_tcp*)(pcap_packet + size_ethernet + size_ip);
	icmp = (struct sniff_icmp*)(pcap_packet + size_ethernet + size_ip);

	//开始剥离MAC层以太网帧
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
        case 0x0800:printf("Data's Type is IP\n");ethernet_ip(ip, tcp, icmp);break;
        case 0x0806:printf("Data's Type is ARP\n");ethernet_arp(arp);break;
        default:break;
    }

	printf("******************END******************\n");
    usleep(800*1000);
}


int main(int argc,char *argv[])
{

    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    //查找网络设备，返回可被 pcap_open_live() 函数调用的网络设备名指针
    dev = pcap_lookupdev(errbuf);
    if(dev==NULL)
    {
        fprintf(stderr,"couldn't find default device: %s\n",errbuf);
        return(2);
    }
    printf("Device: %s\n",dev);

    //获得指定网络设备的网络号和掩码 
    bpf_u_int32 netp = 0;
    bpf_u_int32 maskp = 0;
    int ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1)
    {
        printf(errbuf);
        return(-1);
    }
    char str_netp[64] = {0};
    inet_ntop(AF_INET, &netp, str_netp, 64);
    char str_mask[64] = {0};
    inet_ntop(AF_INET, &maskp, str_mask, 64);
    printf("net = %s, mask = %s\n", str_netp, str_mask);

    //打开网络设备，并且返回用于捕获网络数据包的数据包捕获描述字
    pcap_t *pcap_handle = pcap_open_live(dev, 1024, 1, 0, errbuf);
    if(NULL == pcap_handle)  
    {  
        printf(errbuf);  
        return(-1);
    }
   
    //捕获数据包
    struct pcap_pkthdr protocol_header;
    const u_char *pcap_packet = pcap_next(pcap_handle, &protocol_header);
    
    //设置过滤条件
    //struct bpf_program filter;
    //pcap_compile(pcap_handle, &filter, "dst port 6802", 1, 0);  //编译 BPF 过滤规则
    //pcap_setfilter(pcap_handle, &filter);  //应用 BPF 过滤规则

    //循环捕获网络数据包，直到遇到错误或者满足退出条件。每次捕获一个数据包就会调用 callback 指定的回调函数进行数据包的处理操作
    ret = pcap_loop(pcap_handle, -1, ethernet_protocol_callback, NULL);
    if(ret < 0)
    {
        perror("pcap_loop");
    }
 
    //关闭 pcap_open_live() 打开的网络接口（即其返回值，pcap_t 类型指针），并释放相关资源。注意，操作完网络接口，应该释放其资源
    pcap_close(pcap_handle);   

    return(0);

}
