#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "config.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    //调用buf_init()对txbuf进行初始化。
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //填写ARP报头。
    arp_pkt_t *arp = (arp_pkt_t *)txbuf.data;
    memcpy(arp, &arp_init_pkt, sizeof(arp_pkt_t));
    //ARP操作类型为ARP_REQUEST，注意大小端转换。
    arp->opcode16 = swap16((uint16_t)ARP_REQUEST);
    memcpy(arp->target_ip, target_ip, NET_IP_LEN);
    //以太网封装的目的MAC地址应该是广播地址
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *arp = (arp_pkt_t *)txbuf.data;
    memcpy(arp, &arp_init_pkt, sizeof(arp_pkt_t));
    arp->opcode16 = swap16((uint16_t)ARP_REPLY);
    memcpy(arp->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp->target_mac, target_mac, NET_MAC_LEN);
    //调用ethernet_out()函数将填充好的ARP报文发送出去。
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    if(buf->len < sizeof(arp_pkt_t))
        return;
    //报头检查
    arp_pkt_t *header = (arp_pkt_t *)buf->data;
    if (header->hw_type16 != swap16(ARP_HW_ETHER)
    || header->pro_type16 != swap16(NET_PROTOCOL_IP)
    || header->hw_len != NET_MAC_LEN
    || header->pro_len != NET_IP_LEN
    || (swap16(header->opcode16) != ARP_REQUEST && swap16(header->opcode16) != ARP_REPLY)
    ) return;
    // TO-DO
    //调用map_set()函数更新ARP表项。
    map_set(&arp_table, header->sender_ip, src_mac); //对每一个arp，保存其ip和mac的对应信息

    //调用map_get()函数查看该接收报文的IP地址是否有对应的arp_buf缓存。
    buf_t *k = map_get(&arp_buf, header->sender_ip); 
    if(k != NULL){
        ethernet_out(k, src_mac, NET_PROTOCOL_IP);//将缓存的数据包arp_buf再发送给以太网层
        map_delete(&arp_buf, header->sender_ip);     //从buf中删除
    }
    //判断接收到的报文是否为ARP_REQUEST请求报文，并且该请求报文的target_ip是本机的IP
    //则认为是请求本主机MAC地址的ARP请求报文，则调用arp_resp()函数回应一个响应报文。
    if(swap16(header->opcode16) == ARP_REQUEST && !memcmp(header->target_ip, net_if_ip, NET_IP_LEN)){
        arp_resp(header->sender_ip, src_mac);        
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *mac = map_get(&arp_table, ip); //先搜索arp表，找对应的mac地址
    if(mac == NULL){
        buf_t *k = map_get(&arp_buf, ip);   //没有就放入buf，如果buf已有此包，丢掉
        if(k == NULL){
            map_set(&arp_buf, ip, buf);
            arp_req(ip);                    //buf没有这个包，还要发送请求arp
        }
        else
            return;
    }
    else
        ethernet_out(buf, mac, NET_PROTOCOL_IP);//从arp表获取mac地址发送的包都是ip协议(上层协议)
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}