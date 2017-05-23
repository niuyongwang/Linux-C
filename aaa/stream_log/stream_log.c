/*********************************************************
* 当前文件:stream.c
* 文件作者:牛永旺
* 电子邮箱:2511955991@qq.com
* 编写时间:Thu 11 May 2017 04:53:22 PM CST
**********************************************************/
#include "pcap_header.h"

//比较五元组
int compare_stream(const struct stream_log *stream_tmp, const struct stream_log *stream_data)
{
	if(strcmp(stream_tmp->src_ipaddr, stream_data->src_ipaddr) == 0)
	{
		if(strcmp(stream_tmp->dst_ipaddr, stream_data->dst_ipaddr) == 0)
		{
			goto NEXT;
		}
		else
		{
			return -1;
		}
	}
	else if(strcmp(stream_tmp->src_ipaddr, stream_data->dst_ipaddr) == 0)
	{
		if(strcmp(stream_tmp->dst_ipaddr, stream_data->src_ipaddr) == 0)
		{
			goto NEXT;
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

NEXT:
	if(stream_tmp->src_port == stream_data->src_port)
	{
		if(stream_tmp->dst_port == stream_data->dst_port)
		{
			goto END;
		}
		else
		{
			return -1;
		}
	}
	else if(stream_tmp->src_port == stream_data->dst_port)
	{
		if(stream_tmp->dst_port == stream_data->src_port)
		{
			goto END;
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
	
END:
	if(strcmp(stream_tmp->pro_type, stream_data->pro_type) == 0)
	{
		return 0;
	}
	else
	{
		return -1;
	}
	return -1;
}

//解析TCP层字段
void tcp_resolve(const struct packet_tcp *tcp, int size_tcphlen, struct stream_log *stream_data)
{
    //获取源port端口和目的port端口
    stream_data->src_port = ntohs(tcp->th_sport);
    stream_data->dst_port = ntohs(tcp->th_dport); 
}

//解析UDP层字段
void udp_resolve(const struct packet_udp *udp, int size_udphlen, struct stream_log *stream_data)
{
    //获取源port端口和目的port端口
    stream_data->src_port = ntohs(udp->th_sport);
    stream_data->dst_port = ntohs(udp->th_dport);
}

//解析IP层字段
void ip_resolve(const struct packet_ip *ip, int size_iphlen, struct stream_log *stream_data)
{	
    //获取源ip地址和目的ip地址
    memcpy(stream_data->src_ipaddr, inet_ntoa(ip->ip_src), strlen(inet_ntoa(ip->ip_src)));
    memcpy(stream_data->dst_ipaddr, inet_ntoa(ip->ip_dst), strlen(inet_ntoa(ip->ip_dst)));

	//有IP分片的return
	if(ntohs(ip->ip_off) == 0x2000)
	{
		return;
	}
	//有偏移量的return
	if((ntohs(ip->ip_off) & 0x00ff) != 0x0000)
	{
		return;
	}

	if(ip->ip_pro == 0x06)
	{
	    //获取协议类型
        strcpy(stream_data->pro_type, "TCP");

        //初始化TCP报文
        struct packet_tcp *tcp; 
		tcp = (struct packet_tcp *)((char *)ip + size_iphlen);
		//求出TCP报文首部长度
        int size_tcphlen = TH_OFF(tcp) * 4;
        //解析TCP报文首部字段
        tcp_resolve(tcp, size_tcphlen, stream_data);
	}
	else if(ip->ip_pro == 0x11)
	{
		//获取协议类型
        strcpy(stream_data->pro_type, "UDP");
		
		//初始化UDP报文
        struct packet_udp *udp; 
		udp = (struct packet_udp *)((char *)ip + size_iphlen);
		//求出UDP报文首部长度
        int size_udphlen = ntohs(udp->th_len);
        //解析UDP报文首部字段
        udp_resolve(udp, size_udphlen, stream_data);
	}
}

//解析MAC层字段
void mac_resolve(const struct packet_ethernet *ethernet, int size_ethlen, struct stream_log *stream_data)
{
    //判断下一层
    if(ntohs(ethernet->ether_type) == 0x0800)
    {
        //初始化IP报文
        struct packet_ip *ip;
        ip = (struct packet_ip *)((char *)ethernet + size_ethlen);
        //求出IP报文首部长度
        int size_iphlen = (ip->ip_hlen & 0x0F) << 2;
        //解析IP报文首部字段
        ip_resolve(ip, size_iphlen, stream_data);
    }
}

//获取数据包
void get_stream(const u_char *packet, struct stream_log *stream_data)
{
    if(packet != NULL)
    {
        //初始化MAC报文
        struct packet_ethernet *ethernet;
	    ethernet = (struct packet_ethernet *)packet;
	    //求出报文首部长度
        int size_ethlen = sizeof(struct packet_ethernet);
        //解析报文首部
        mac_resolve(ethernet, size_ethlen, stream_data);    
    }
}


//查找所属的TCP流
int find_hash_table(const struct hash_table *stream_hash, const struct stream_log *stream_data)
{
    int i = 0;
    for(i = 0; i < sizeof(struct hash_table)/8; ++i)
    {
        //将流组中的每个流，赋值给临时流，然后遍历每个临时流
        struct stream_log *stream_tmp = stream_hash->stream[i];
        if(stream_tmp == NULL)
        {
            continue;
        }
        //与每个五元组进行比较
        if(compare_stream(stream_tmp, stream_data) == 0)
        {
            return i;
        }
    }
    return -1;
}

//插入新的TCP流
int instert_hash_table(struct hash_table *stream_hash, const struct stream_log *stream_data)
{
    int i = 0;
    for(i = 0; i < sizeof(struct hash_table)/8; ++i)
    {
        //遍历这个流组，找个空的位置，分配空间并插入数据包，完成TCP流组的添加
        struct stream_log *stream_tmp = stream_hash->stream[i];
        if(stream_tmp == NULL)
        {
            stream_tmp = (struct stream_log *)malloc(sizeof(struct stream_log));
            memset(stream_tmp, 0, sizeof(struct stream_log));
            memcpy(stream_tmp->src_ipaddr, stream_data->src_ipaddr, strlen(stream_data->src_ipaddr)+1);
            memcpy(stream_tmp->dst_ipaddr, stream_data->dst_ipaddr, strlen(stream_data->dst_ipaddr)+1);
            memcpy(stream_tmp->pro_type, stream_data->pro_type, strlen(stream_data->pro_type)+1);
            stream_tmp->src_port = stream_data->src_port;
            stream_tmp->dst_port = stream_data->dst_port;
            stream_tmp->updata_len = stream_data->updata_len;
            stream_tmp->uppack_sum = stream_data->uppack_sum;
            stream_tmp->downdata_len = stream_data->downdata_len;
            stream_tmp->downpack_sum = stream_data->downpack_sum;
            stream_hash->stream[i] = stream_tmp;
            return 0;
        }
        continue;
    }
	return -1;
}

//更新旧的TCP流
int update_hash_table(struct stream_log *stream_key, const struct stream_log *stream_data)
{
    stream_key->updata_len += stream_data->updata_len;
    stream_key->uppack_sum += stream_data->uppack_sum;
    stream_key->downdata_len += stream_data->downdata_len;
    stream_key->downpack_sum += stream_data->downpack_sum;
    return 0;
}

//写入到本地文件中
int write_stream(FILE *fp, struct hash_table *stream_hash)
{
	int stream_len = sizeof(struct stream_log)*2;
    char buf[stream_len];
	int i = 0;
    for(i = 0; i < sizeof(struct hash_table)/8; ++i)
	{
		struct stream_log *stream_tmp = stream_hash->stream[i];
        if(stream_tmp == NULL)  //这个判断很重要
        {
            continue;
        }
        memset(buf, 0, sizeof(buf));
		sprintf(buf, "%-15s | %5d | %-15s | %5d | %5s | %5d | %5d | %5d | %5d \n", stream_tmp->src_ipaddr, stream_tmp->src_port, 
        stream_tmp->dst_ipaddr, stream_tmp->dst_port, stream_tmp->pro_type, stream_tmp->uppack_sum, stream_tmp->updata_len, 
        stream_tmp->downpack_sum, stream_tmp->downdata_len);
		fputs(buf, fp);
	}
    return 0;
}


//处理数据包的回调函数
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct stream_log *stream_data = (struct stream_log *)args;
	memset(stream_data, 0, sizeof(struct stream_log));
	
    //获取五元祖
    get_stream(packet, stream_data);
	
	if(stream_data->src_ipaddr == NULL || stream_data->dst_ipaddr == NULL || stream_data->pro_type == NULL ||
	   stream_data->src_port == 0 || stream_data->dst_port == 0)
	{
		return;
	}
    
	//获取上下行流量
    if(strcmp(stream_data->src_ipaddr, stream_data->dst_ipaddr) < 0)
    {
        stream_data->updata_len = header->caplen;
        stream_data->uppack_sum = 1;
    }
    else if(strcmp(stream_data->src_ipaddr, stream_data->dst_ipaddr) > 0)
    {
        stream_data->downdata_len = header->caplen;
        stream_data->downpack_sum = 1;
    }
/*
	printf("src_ipaddr = %s\n", stream_data->src_ipaddr);
    printf("src_port   = %d\n", stream_data->src_port);
    printf("dst_ipaddr = %s\n", stream_data->dst_ipaddr);
    printf("dst_port   = %d\n", stream_data->dst_port);
    printf("src_ipaddr = %s\n", stream_data->pro_type);
    printf("updata     = %d\n", stream_data->updata_len);
    printf("uppack     = %d\n", stream_data->uppack_sum);
    printf("downdata   = %d\n", stream_data->downdata_len);
    printf("downpack   = %d\n", stream_data->downpack_sum);
    printf("**************************\n");
*/
	//查找所属的TCP流
    int stream_key = find_hash_table(stream_hash, stream_data);
    if(stream_key == -1)
    {
		//插入新的TCP流
        int ret = instert_hash_table(stream_hash, stream_data);
		if(ret == -1)
		{
			printf("instert_hash_table error!\n");
			return;
		}
    }
    else
    {
		//更新旧的TCP流
        int ret = update_hash_table(stream_hash->stream[stream_key], stream_data);
        if(ret == -1)
        {
            printf("update_hash_table error!\n");
            return;
        }
    }
}

//释放内存
void free_stream(struct hash_table *steram_hash)
{
    int i = 0;
    for(i = 0; i < sizeof(struct hash_table)/8; ++i)
    {
        free(stream_hash->stream[i]);
        stream_hash->stream[i] = NULL;
    }
    free(stream_hash);
    stream_hash = NULL;
}

int main(int argc, char* argv[])
{
    int ret = 0;
    
    //存放TCP流
    stream_hash = (struct hash_table *)malloc(sizeof(struct hash_table));
	if(stream_hash == NULL)
	{
		printf("stream_hash malloc error!\n");
		return -1;
	}
    memset(stream_hash, 0, sizeof(struct hash_table));
    printf("streuc hash_table size is %d\n", sizeof(struct hash_table));	

    //存放五元组
	struct stream_log *stream_data = (struct stream_log *)malloc(sizeof(struct stream_log));
	if(stream_data == NULL)
	{
		printf("stream_data malloc error!\n");
		return -1;
	}
	memset(stream_data, 0, sizeof(struct stream_log));
	
	//新建本地文件
	FILE *fp = fopen("log.txt", "w");
	if(fp == NULL)
	{
		printf("fopen error !\n");
		return 0;
	}
	
    //打开.pcap文件
	char error_buf[128] = {0};
	pcap_t *handle = pcap_open_offline("./rty.pcapng", error_buf);
    if(handle == NULL)
    {
        printf("pcap_open_offline error!\n");
    }

	//循环处理数据包
    ret = pcap_loop(handle, -1, loop_callback, (u_char*)stream_data);
	if(ret == -1)
	{
		printf("pcap_loop error\n");
		return -1;
	}
	
	//写入到本地文件
	ret = write_stream(fp, stream_hash);
	if(ret == -1)
	{
		printf("write_stream error!\n");
		return;
	}

    //关闭本地文件,释放内存
	fclose(fp);
	free(stream_data);
    pcap_close(handle);
    free_stream(stream_hash);
    printf("************************************\n");
	return 0;
}

