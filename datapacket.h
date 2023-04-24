#ifndef DATAPACKET_H
#define DATAPACKET_H
#define WIN32
#include "pcap.h"
#include <QString>
#include <QMetaType>
class dataPacket
{
public:
    dataPacket();
private:
    // {"NO.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}
    // 数据包信息
    const u_char * pkt_data;
    QString time;
    u_int length;

//    QString sMacAddr;
//    QString dMacAddr;
//    QString netProtocol;
//    QString info;
public:
    // 固定属性（必定有的）
    void setPkt_data(const u_char * pkt_data, int length);
    void setTime(QString time);
    QString getTime();
    void setLength(u_int length);
    u_int getLength();
    u_short getNetProtocol();
    QString getSMacAddr();
    QString getDMacAddr();

    QString byteToHex(u_char str);
    // IPv4属性
    u_char getIPv4Ver(u_char offset);
    u_char getIPv4Hlen(u_char offset);
    u_char getIPv4Tos(u_char offset);
    u_short getIPv4Tlen(u_char offset);
    u_short getIpv4Identification(u_char offset);
    u_short getIpv4Flags(u_char offset);
    u_short getIpv4Offset(u_char offset);
    u_char getIpv4Ttl(u_char offset);
    u_char getIpv4Protocol(u_char offset);
    u_short getIpv4Crc(u_char offset);
    QString getIpv4SAddr(u_char offset);
    QString getIpv4DAddr(u_char offset);
//    u_int getIpv4Option_pad();

    // tcp属性
    u_short getTcpSport(u_char offset);
    u_short getTcpDport(u_char offset);
    u_int getTcpSeq(u_char offset);
    u_int getTcpAck(u_char offset);
    u_short getTcpHlen_keep_stat(u_char offset);
    u_short getTcpWinsize(u_char offset);
    u_short getTcpChecksum(u_char offset);
    u_short getTcpUrg_ptr(u_char offset);
    u_int getTcpOption(u_char offset);

    // udp属性
    u_short getUdpSport(u_char offset);
    u_short getUdpDport(u_char offset);
    u_short getUdpLen(u_char offset);
};
Q_DECLARE_METATYPE(dataPacket);
#endif // DATAPACKET_H

