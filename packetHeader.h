#ifndef PACKETHEADER_H
#define PACKETHEADER_H

#endif // PACKETHEADER_H
#define WIN32
//#include <QString>
#include "pcap.h"

//// 6字节MAC地址
//typedef struct MACAddress{
//    u_char byte1;
//    u_char byte2;
//    u_char byte3;
//    u_char byte4;
//    u_char byte5;
//    u_char byte6;
//} MACAddress;

// 以太网头部
typedef struct etherHeader{
    u_char dMacAddr[6]; // 源MAC地址
    u_char sMacAddr[6]; // 目的MAC地址
    u_short type; // 类型（0800：IPv4，0806：ARP）
} etherHeader;

// ARP请求
#pragma pack(1) // 阻止结构体自动对齐
typedef struct arpHeader{
    u_short hardwareType; // 硬件类型
    u_short protoType; // 协议类型，表示要映射的协议地址的类型，ipv4为0x0800
    u_char hardwareSize; // 硬件地址长度，MAC地址6字节
    u_char protoSize; // 协议地址长度，IP地址4字节
    u_short opCode; // 1表示ARP请求，2表示ARP应答，3表示RARP请求，4为RAPR应答
    u_char sMacAddr[6]; // 源MAC地址
    u_int sAddr; //源IP地址
    u_char dMacAddr[6]; // 目的MAC地址
    u_int dAddr; // 目的IP地址
} arpHeader;

// ipv4头部
typedef struct ipv4Header{
    u_char ver_hlen; // 版本（高四位）， 头部长度（低四位，单位是4字节），注意大小端的不同
    u_char tos; // 8位服务类型
    u_short tlen; // 16位总长度(字节数)
    u_short identification; // 16位标识
    u_short flags_offset; // 标志位（高三位），段偏移量（低十三位），注意大小端的不同
    u_char ttl; // 8位生存时间
    u_char protocol; // 8位协议
    u_short checkSum; // 16位首部校验和
    u_int sAddr; // 源地址（32位）
    u_int dAddr; // 目的地址（32位）
    u_int option_pad; // 选项与填充（32位）
} ipHeader;

// ipv6头部，这里不考虑扩展首部（仅考虑next header为6（对应TCP）和7（对应UDP））
typedef struct ipv6Header{
    u_int ver_tc_fl; // 版本（高4位），traffic class（次8位），flow label流标签（低20位）
    u_short len; // 数据包长度， 16位
    u_char nextHeader; // next header， 6：TCP， 17：UDP
    u_char HL; // Hop Limit
    char sAddr[16];
    char dAddr[16];
} ipv6Header;

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
} tcpHeader;

// udp头部
typedef struct udpHeader{
    u_short sPort; // 源端口号（16位）
    u_short dPort; // 目的端口号（16位）
    u_short len; // 数据包长度（16位，单位是字节）
    u_short checksum; // 校验和
} udpHeader;

