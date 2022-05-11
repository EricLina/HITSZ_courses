#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "utils.h"


// 用于id16 自增
uint16_t increments = 0;

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    
    ip_hdr_t* ip_hdr = (ip_hdr_t *) buf->data;
    uint16_t flags_fragment = swap16(ip_hdr->flags_fragment16);
    size_t totol_len = swap16(ip_hdr->total_len16);

    if(buf->len < sizeof(ip_hdr_t)) return ;
    if(ip_hdr->version !=IP_VERSION_4 || 
        ip_hdr->hdr_len < sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE ||
        ((flags_fragment & IP_MORE_FRAGMENT) && ((totol_len - sizeof(ip_hdr_t)%8 !=0))) ||
        totol_len < sizeof(ip_hdr) ||
        ip_hdr ->ttl <=0 
          )  
    return;


    //检查IP
	if (memcmp(net_if_ip, ip_hdr->dst_ip, NET_IP_LEN) != 0)
	{// 目的IP不是本机IP, 不处理
		return;
	}
    
    // 检查校验和
    uint16_t tmp_checksum  = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t *) ip_hdr,sizeof(ip_hdr_t));
    ip_hdr->hdr_checksum16 = tmp_checksum; //复原
    if(checksum != tmp_checksum) 
    {return;
    }


    //检查填充字段,数据包的长度大于IP头部的总长度字段，则说明该数据包有填充字段
    if(buf->len > totol_len){
        buf_remove_padding(buf,buf->len - totol_len);
    }
        

    //检查协议字段
    // switch (ip_hdr->protocol) {
    //     case NET_PROTOCOL_ICMP:
    //         buf_remove_header(buf, sizeof(ip_hdr_t));
    //         icmp_in(buf, ip_hdr->src_ip) ;
    //         break;
    //     case NET_PROTOCOL_UDP:
    //         buf_remove_header(buf, sizeof(ip_hdr_t));
    //         udp_in(buf, ip_hdr->src_ip);
    //         break;
    //     default:
    //         icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    //         break;     
    // }
    if(ip_hdr->protocol==NET_PROTOCOL_ICMP || ip_hdr->protocol==NET_PROTOCOL_UDP){
        buf_remove_header(buf, sizeof(ip_hdr_t));
        net_in(buf,ip_hdr->protocol,ip_hdr->src_ip);    
    }
    else{
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;

    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->version = IP_VERSION_4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    //爲什麽只有16位的需要swap
    hdr->id16 = swap16(id);

    hdr->flags_fragment16 = swap16(offset + (mf << 13));

    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;

    
    //IP
    memcpy(hdr->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(hdr->dst_ip,ip,NET_IP_LEN);

    //checksum
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *) hdr, sizeof(ip_hdr_t));
    
    //send out 
    // printf("dstEndpt: %s", ip);
    // printf("buflen: %lld",buf->len);
    memcpy(buf->data,hdr,sizeof(ip_hdr_t));
    arp_out(buf, ip); // 默认NET_PROTOCOL_IP
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // 检验数据包长度是否大于IP协议的最大负载包长度
    int offset = 0;
    int mf =0;

    int maxlen=ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    if(buf->len  <= maxlen){
        ip_fragment_out(buf,ip,protocol,increments,offset,mf);
    }
    else{// 分片
        uint16_t left_length = buf->len;
        int  count =0;
        mf =1;

        buf_t  ip_buf;
        buf_t *frag_buf = &ip_buf;
        
        while(left_length >= maxlen){//对n-1个分组发送
            buf_init(frag_buf, maxlen);
            memcpy(frag_buf->data,buf->data,maxlen);
            offset =(count * (maxlen)) >> 3;
            ip_fragment_out(frag_buf, ip, protocol, increments, offset, mf);
            buf_remove_header(buf, maxlen);
            count +=1 ; 
            left_length-= maxlen;
        }
        //对最后一个分组发送
        if (left_length>0){
            buf_init(frag_buf,left_length);//初始化buf
            frag_buf->len=left_length;
            frag_buf->data = buf->data;
            // 因为offset必须是3的倍数，所以还是用(count * (maxlen)) >> 3，而不是left_len
            ip_fragment_out(frag_buf, ip, protocol, increments, (count * (maxlen)) >> 3, 0); 
        }

    }
    increments+=1;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}