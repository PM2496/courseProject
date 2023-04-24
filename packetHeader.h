#ifndef PACKETHEADER_H
#define PACKETHEADER_H

#endif // PACKETHEADER_H
#define WIN32
//#include <QString>
#include "pcap.h"

// 6字节MAC地址
typedef struct MACAddress{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
} MACAddress;

// 以太网头部
typedef struct etherHeader{
    MACAddress sMacAddr; // 源MAC地址
    MACAddress dMacAddr; // 目的MAC地址
    u_short type; // 类型（0800：IPv4，0806：ARP，8035：RARP）
} etherHeader;

// ipv4头部
typedef struct ipv4Header{
    u_char ver_hlen; // 版本（低四位）， 头部长度（高四位，单位是4字节），注意大小端的不同
    u_char tos; // 8位服务类型
    u_short tlen; // 16位总长度(字节数)
    u_short identification; // 16位标识
    u_short flags_offset; // 标志位（低三位），段偏移量（高十三位），注意大小端的不同
    u_char ttl; // 8位生存时间
    u_char protocol; // 8位协议
    u_short crc; // 16位首部校验和
    u_int sAddr; // 源地址（32位）
    u_int dAddr; // 目的地址（32位）
    u_int option_pad; // 选项与填充（32位）
} ipHeader;

//typedef struct ipv6Header{

//};

// tcp头部
typedef struct tcpHeader{
    u_short sPort; // 源端口号（16位）
    u_short dPort; // 目的端口号（16位）
    u_int seq; // 序列号（32位）
    u_int ack; // 确认号（32位）
    u_short hlen_keep_stat; // 头部长度（4位，单位是4字节）， 保留（6位）， URG，ACK，PSH，RST，SYN，FIN
    u_short winSize; // 窗口大小（16位）
    u_short checkSum; // Tcp校验和（16位）
    u_short urg_ptr; // 紧急指针（16位）
    u_int option; // 选项（32位）
} tcpHeader;

// udp头部
typedef struct udpHeader{
    u_short sPort; // 源端口号（16位）
    u_short dPort; // 目的端口号（16位）
    u_short len; // 数据包长度（16位，单位是字节）
} udpHeader;



// http头部
typedef struct httpHeader{

} httpHeader;
