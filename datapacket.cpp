#include "datapacket.h"
#include "packetHeader.h"
#include "winsock2.h"
#include <QMetaType>
dataPacket::dataPacket()
{
    qRegisterMetaType<dataPacket>("dataPacket");
    this->pkt_data = nullptr;
    this->time = "";
    this->length = 0;

}
void dataPacket::setPkt_data(const u_char *pkt_data, int length){
    this->pkt_data = (u_char*)malloc(length);
    if(this->pkt_data != nullptr)
        memcpy((char*)(this->pkt_data),pkt_data,length);
    else this->pkt_data = nullptr;
}

void dataPacket::setTime(QString time){
    this->time = time;
}

QString dataPacket::getTime(){
    return time;
}

void dataPacket::setLength(u_int length){
    this->length = length;
}

u_int dataPacket::getLength(){
    return length;
}


u_short dataPacket::getNetProtocol(){
    etherHeader * header = (etherHeader *)pkt_data;
    u_short type = ntohs(header->type);
//    switch(type){
//    case 0x0800:
//        return "IPv4";
//        break;
//    case 0x86DD:
//        return "IPv6";
//        break;
//    case 0x0806:
//        return "ARP";
//        break;
//    default:
//        return "Don't care";
//        break;
//    }
    return type;
}


QString dataPacket::getSMacAddr(){
    etherHeader * header = (etherHeader *)pkt_data;
    MACAddress addr = header->sMacAddr;
    // 格式化输出
    QString Addr = byteToHex(addr.byte1) + ":"
                        + byteToHex(addr.byte2) + ":"
                        + byteToHex(addr.byte3) + ":"
                        + byteToHex(addr.byte4) + ":"
                        + byteToHex(addr.byte5) + ":"
                        + byteToHex(addr.byte6);
    return Addr;
}

QString dataPacket::getDMacAddr(){
    etherHeader * header = (etherHeader *)pkt_data;
    MACAddress addr = header->dMacAddr;
    QString Addr = byteToHex(addr.byte1) + ":"
                        + byteToHex(addr.byte2) + ":"
                        + byteToHex(addr.byte3) + ":"
                        + byteToHex(addr.byte4) + ":"
                        + byteToHex(addr.byte5) + ":"
                        + byteToHex(addr.byte6);
    return Addr;
}
// 字节转16进制
QString dataPacket::byteToHex(u_char str){
    QString res = "";
    char high = str >> 4;
    if(high >= 0x0A)
        high = high + 0x41 - 0x0A;
    else
        high = high + 0x30;

    char low = str & 0xF;

    if(low >= 0x0A)
        low = low  + 0x41 - 0x0A;
    else
        low = low + 0x30;

    res.append(high);
    res.append(low);

    return res;
}

// IPv4属性
u_char dataPacket::getIPv4Ver(u_char offset){
    // 高4位
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return (header->ver_hlen)>>4;
}

u_char dataPacket::getIPv4Hlen(u_char offset){
    // 低四位
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return ((header->ver_hlen)&0xF)*4;
}

u_char dataPacket::getIPv4Tos(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return header->tos;
}

u_short dataPacket::getIPv4Tlen(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    // 多字节数据需要进行大小端的转换
    return ntohs(header->tlen);
}

u_short dataPacket::getIpv4Identification(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return ntohs(header->identification);
}

u_short dataPacket::getIpv4Flags(u_char offset){
    // 高3位
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return ntohs(header->flags_offset)>>13;
}

u_short dataPacket::getIpv4Offset(u_char offset){
    // 低13位
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return ntohs(header->flags_offset)&0x1FFF;
}

u_char dataPacket::getIpv4Ttl(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return header->ttl;
}

u_char dataPacket::getIpv4Protocol(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return header->protocol;
}

u_short dataPacket::getIpv4Crc(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    return ntohs(header->crc);
}

QString dataPacket::getIpv4SAddr(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    sockaddr_in addr;
    addr.sin_addr.s_addr = header->sAddr;
    return QString(inet_ntoa(addr.sin_addr));
}

QString dataPacket::getIpv4DAddr(u_char offset){
    ipv4Header * header = (ipv4Header *)(pkt_data+offset);
    sockaddr_in addr;
    addr.sin_addr.s_addr = header->dAddr;
    return QString(inet_ntoa(addr.sin_addr));
}

//u_int dataPacket::getIpv4Option_pad(){

//}

//// tcp属性
u_short dataPacket::getTcpSport(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohs(header->sPort);
}

u_short dataPacket::getTcpDport(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohs(header->dPort);
}

u_int dataPacket::getTcpSeq(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohl(header->seq);
}

u_int dataPacket::getTcpAck(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohl(header->ack);
}

u_short dataPacket::getTcpHlen_keep_stat(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
//    // 高四位为头部长度，单位为4字节
//    return ((ntohs(header->hlen_keep_stat))>>12)*4;
    return ntohs(header->hlen_keep_stat);
}

u_short dataPacket::getTcpWinsize(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohs(header->winSize);
}

u_short dataPacket::getTcpChecksum(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohs(header->checkSum);
}

u_short dataPacket::getTcpUrg_ptr(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohs(header->urg_ptr);
}

u_int dataPacket::getTcpOption(u_char offset){
    tcpHeader * header = (tcpHeader *)(pkt_data + offset);
    return ntohl(header->option);
}

//// udp属性
//u_short dataPacket::getUdpSport(){

//}

//u_short dataPacket::getUdpDport(){

//}

//u_short dataPacket::getUdpLen(){

//}
