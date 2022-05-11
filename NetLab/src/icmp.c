#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{   
    icmp_hdr_t * icmp_in_hdr = (icmp_hdr_t *) req_buf->data;

    int ICMP_HEADER_LEN = sizeof(icmp_hdr_t); // ICMP 首部
    
    buf_t * txbuf_p = &txbuf;
    buf_init(txbuf_p, req_buf->len );
    memcpy(txbuf_p->data,req_buf->data,req_buf->len) ; 

    icmp_hdr_t icmp_out_hdr = {
    .type = ICMP_TYPE_ECHO_REPLY,
    .code = icmp_in_hdr->code,
    .checksum16 = 0,
    .id16 = icmp_in_hdr->id16,
    .seq16 = icmp_in_hdr->seq16};
    //校验和
    memcpy(txbuf_p->data , &icmp_out_hdr, ICMP_HEADER_LEN);

    icmp_out_hdr.checksum16 = checksum16((uint16_t *) txbuf_p->data, txbuf_p->len) ;
    memcpy(txbuf_p->data , &icmp_out_hdr, ICMP_HEADER_LEN);


    ip_out(txbuf_p,src_ip,NET_PROTOCOL_ICMP);
    
}
    

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    icmp_hdr_t * icmp_hdr =(icmp_hdr_t * ) buf ->data;
    //长度
    if(buf->len < sizeof(icmp_hdr_t)) {
        return ;
    }
    if(icmp_hdr->type != ICMP_TYPE_ECHO_REQUEST){
        // 发送过来的ICMP类型应该为 回显请求
        return ;
    }
    icmp_resp(buf , src_ip);
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    int ICMP_HEADER_LEN = sizeof(icmp_hdr_t); // ICMP 首部
    int IP_HEADER_LEN = sizeof(ip_hdr_t);     // IP首部
    int ICMP_ERR_IP_DATA_LEN = 8;             // ICMP差错报文 的 8 字节

    buf_t * txbuf_p = &txbuf;
    buf_init(txbuf_p, IP_HEADER_LEN +ICMP_ERR_IP_DATA_LEN );
    memcpy(txbuf_p->data,recv_buf->data,IP_HEADER_LEN +ICMP_ERR_IP_DATA_LEN);

    buf_add_header(txbuf_p,ICMP_HEADER_LEN);
    icmp_hdr_t icmp_err_hdr = {
    .type = ICMP_TYPE_UNREACH,
    .code = code,
    .checksum16 = 0,
    .id16 = 0,
    .seq16 = 0};
    memcpy(txbuf_p->data , &icmp_err_hdr, ICMP_HEADER_LEN);
    // memcpy(txbuf_p->data + ICMP_HEADER_LEN , recv_buf->data , IP_HEADER_LEN + ICMP_ERR_IP_DATA_LEN);
    icmp_err_hdr.checksum16 = checksum16((uint16_t *)txbuf.data, txbuf_p->len);
    memcpy(txbuf_p->data , &icmp_err_hdr, ICMP_HEADER_LEN);

    // icmp_hdr_t * icmp_in_hdr = (icmp_hdr_t *) recv_buf->data;
    // uint16_t id = swap16(icmp_in_hdr->id16) ;
    ip_out(txbuf_p, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}