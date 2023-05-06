#include "multhread.h"
#include <QDebug>
#include <direct.h>
multhread::multhread()
{
    this->isDone = true;
    this->filePath = QString(getcwd(NULL, 100)) + "\\temp.pcap";
}

bool multhread::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer)
        dumpfile = pcap_dump_open(pointer, filePath.toLatin1());
        return true;
    return false;
}

void multhread::setDumpfile(pcap_dumper_t * dumpfile){
    this->dumpfile = dumpfile;
}

QString multhread::getFilePath(){
    return this->filePath;
}

pcap_dumper_t * multhread::getDumpfile(){
    return this->dumpfile;
}

void multhread::setFlag(){
    this->isDone = false;
}

void multhread::resetFlag(){
    this->isDone = true;
}

void multhread::run(){
    while(true){
        if(isDone)
            break;
        int res = pcap_next_ex(pointer, &header, &pkt_data);
        if(res == 0)
            continue;
        pcap_dump((u_char *)dumpfile, header, pkt_data);
        local_time_sec = header->ts.tv_sec;
        localtime_s(&local_time, &local_time_sec);
        strftime(timeString, sizeof(timeString), "%H:%M:%S", &local_time);
//        qDebug() << "caplen=" << header->caplen;
        dataPacket packet;
        packet.setLength(header->len);
        packet.setPkt_data(pkt_data, header->len);
        packet.setTime(timeString);
        emit getPkt_data(packet);
    }
}

