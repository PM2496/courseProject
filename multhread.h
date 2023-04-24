#ifndef MULTHREAD_H
#define MULTHREAD_H
#define WIN32
#include <QThread>
#include "pcap.h"
#include "datapacket.h"
class multhread: public QThread
{
    Q_OBJECT
public:
    multhread();
    bool setPointer(pcap_t * pointer);
    void setFlag();
    void resetFlag();
    void run() override;
signals:
    void getPkt_data(dataPacket packet);
private:
    pcap_t * pointer;
    struct pcap_pkthdr * header;
    const u_char * pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
};

#endif // MULTHREAD_H
