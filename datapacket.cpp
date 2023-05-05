#include "datapacket.h"
#include "packetHeader.h"
#include "winsock2.h"
#include <QMetaType>
#include <QDebug>
dataPacket::dataPacket()
{
    qRegisterMetaType<dataPacket>("dataPacket");
    this->pkt_data = nullptr;
    this->time = "";
    this->length = 0;
    this->protocol = "";

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

void dataPacket::setSAddr(QString addr){
    this->sAddr = addr;
}

QString dataPacket::getSAddr(){
    return this->sAddr;
}

void dataPacket::setDAddr(QString addr){
    this->dAddr = addr;
}

QString dataPacket::getDAddr(){
    return this->dAddr;
}

void dataPacket::setInfo(QString info){
    this->info += info;
}

QString dataPacket::getInfo(){
    return this->info;
}

void dataPacket::setProtocol(QString proto){
   this->protocol = proto;
}

QString dataPacket::getProtocol(){
    return this->protocol;
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
    u_char * addr = header->sMacAddr;
    // 格式化输出
    QString Addr = byteToHex(addr[0]) + ":"
                        + byteToHex(addr[1]) + ":"
                        + byteToHex(addr[2]) + ":"
                        + byteToHex(addr[3]) + ":"
                        + byteToHex(addr[4]) + ":"
                        + byteToHex(addr[5]);
    return Addr;
}

QString dataPacket::getDMacAddr(){
    etherHeader * header = (etherHeader *)pkt_data;
    u_char * addr = header->dMacAddr;
    // 格式化输出
    QString Addr = byteToHex(addr[0]) + ":"
                        + byteToHex(addr[1]) + ":"
                        + byteToHex(addr[2]) + ":"
                        + byteToHex(addr[3]) + ":"
                        + byteToHex(addr[4]) + ":"
                        + byteToHex(addr[5]);
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

// ARP属性
QString dataPacket::getArpHType(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    u_short type = ntohs(header->hardwareType);
    // 等于1表示以太网
    if (type == 1){
        return QString("Ethernet (1)");
    }
    else{
        return QString::number(type);
    }
}

QString dataPacket::getArpProType(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    u_short type = ntohs(header->protoType);
    // 0x0800表示ipv4
    if (type == 0x0800){
        return QString("IPv4 (0x0800)");
    }
    else{
        return "0x"+byteToHex(type>>4 & 0xF)+byteToHex(type & 0xF); // 转化为16进制显示
    }
}

u_char dataPacket::getArpHSize(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    return header->hardwareSize;
}

u_char dataPacket::getArpProSize(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    return header->protoSize;
}

u_short dataPacket::getArpOpCode(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    return ntohs(header->opCode);
}

QString dataPacket::getArpSMacAddr(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    u_char * addr = header->sMacAddr;
    // 格式化输出
    QString Addr = byteToHex(addr[0]) + ":"
                        + byteToHex(addr[1]) + ":"
                        + byteToHex(addr[2]) + ":"
                        + byteToHex(addr[3]) + ":"
                        + byteToHex(addr[4]) + ":"
                        + byteToHex(addr[5]);
    return Addr;
}

QString dataPacket::getArpSAddr(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    sockaddr_in addr;
    addr.sin_addr.s_addr = header->sAddr;
    return QString(inet_ntoa(addr.sin_addr));
}

QString dataPacket::getArpDMacAddr(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    u_char * addr = header->dMacAddr;
    // 格式化输出
    QString Addr = byteToHex(addr[0]) + ":"
                        + byteToHex(addr[1]) + ":"
                        + byteToHex(addr[2]) + ":"
                        + byteToHex(addr[3]) + ":"
                        + byteToHex(addr[4]) + ":"
                        + byteToHex(addr[5]);
    return Addr;
}

QString dataPacket::getArpDAddr(u_char offset){
    arpHeader * header = (arpHeader *)(pkt_data+offset);
    sockaddr_in addr;
    addr.sin_addr.s_addr = header->dAddr;
    return QString(inet_ntoa(addr.sin_addr));
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

// IPv6属性
u_int dataPacket::getIpv6Ver_tc_fl(u_char offset){
    ipv6Header * header = (ipv6Header *)(pkt_data + offset);
    return header->ver_tc_fl;
}

u_short dataPacket::getIpv6Len(u_char offset){
    ipv6Header * header = (ipv6Header *)(pkt_data + offset);
    return header->len;
}

u_char dataPacket::getIpv6NextHeader(u_char offset){
    ipv6Header * header = (ipv6Header *)(pkt_data + offset);
    return header->nextHeader;
}

u_char dataPacket::getIpv6HL(u_char offset){
    ipv6Header * header = (ipv6Header *)(pkt_data + offset);
    return header->HL;
}

QString dataPacket::getIpv6SAddr(u_char offset){
    ipv6Header * header = (ipv6Header *)(pkt_data + offset);
    char * sAddr = header->sAddr;
    QString addr = "";
    for(int i=0; i<16; ){
        addr += byteToHex(sAddr[i++]);
        addr += byteToHex(sAddr[i++]);
        if(i == 16)
            continue;
        addr += ":";
    }
    return addr;
}

QString dataPacket::getIpv6DAddr(u_char offset){
    ipv6Header * header = (ipv6Header *)(pkt_data + offset);
    char * dAddr = header->dAddr;
    QString addr = "";
    for(int i=0; i<16; ){
        addr += byteToHex(dAddr[i++]);
        addr += byteToHex(dAddr[i++]);
        if(i == 16)
            continue;
        addr += ":";
    }
    return addr;
}

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

u_char * dataPacket::getTcpOption(u_char offset){
    return (u_char *)(pkt_data + offset + 20);
}

// udp属性
u_short dataPacket::getUdpSport(u_char offset){
    udpHeader * header = (udpHeader *)(pkt_data + offset);
    return ntohs(header->sPort);
}

u_short dataPacket::getUdpDport(u_char offset){
    udpHeader * header = (udpHeader *)(pkt_data + offset);
    return ntohs(header->dPort);
}

u_short dataPacket::getUdpLen(u_char offset){
    udpHeader * header = (udpHeader *)(pkt_data + offset);
    return ntohs(header->len);
}

QString dataPacket::getUdpCheckSum(u_char offset){
    udpHeader * header = (udpHeader *)(pkt_data + offset);
    u_short checksum = ntohs(header->checksum);
    return "0x"+byteToHex(checksum>>8 & 0xF)+byteToHex(checksum & 0xF);
}

QString dataPacket::getUdpData(u_char offset){
    udpHeader * header = (udpHeader *)(pkt_data + offset);
    u_char * pData = (u_char *)(pkt_data + offset + 8);
    u_short dataLength = ntohs(header->len)-8;
    QString data = "";
    if(dataLength>0){
        for(int i=0; i<dataLength; i++){
            data += byteToHex(pData[i]);
        }
    }
    return data;
}
