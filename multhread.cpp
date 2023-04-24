#include "multhread.h"
#include <QDebug>

multhread::multhread()
{
    this->isDone = true;
}

bool multhread::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer)
        return true;
    return false;
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

