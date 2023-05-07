#ifndef MULTHREAD_H
#define MULTHREAD_H
#define WIN32
#include <QThread>
#include "pcap.h"
#include "datapacket.h"
#include <QString>
class multhread: public QThread
{
    Q_OBJECT
public:
    multhread();
    void setIsReadingFile();
    void resetIsReadingFile();
    bool getIsReadingFile();
    bool setPointer(pcap_t * pointer);
    void setDumpfile(pcap_dumper_t * dumpfile);
    pcap_dumper_t * getDumpfile();
    QString getFilePath();
    void setFlag();
    void resetFlag();
    void run() override;
signals:
    void stopReadFile();
    void getPkt_data(dataPacket packet);
private:
    pcap_t * pointer;
    struct pcap_pkthdr * header;
    const u_char * pkt_data;
    bool isReadingFile; // 判断是读取本地文件还是网络流
    pcap_dumper_t * dumpfile; // 临时文件
    QString filePath; // 临时文件路径
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
};

#endif // MULTHREAD_H
