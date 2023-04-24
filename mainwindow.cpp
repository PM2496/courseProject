#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <QDebug>
#include <QStringList>
#include <QMessageBox>
#include <QColor>
#include "multhread.h"
#include "packetHeader.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    counterNum = 0;
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = {"NO.", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);

    ui->tableWidget->setColumnWidth(0, 75);
    ui->tableWidget->setColumnWidth(1, 150);
    ui->tableWidget->setColumnWidth(2, 300);
    ui->tableWidget->setColumnWidth(3, 300);
    ui->tableWidget->setColumnWidth(4, 150);
    ui->tableWidget->setColumnWidth(5, 100);
    ui->tableWidget->setColumnWidth(6, 1000);



    this->showAdapter();
    multhread * thread = new multhread;

    // 起始状态未选择适配器，两个按键均无法按下
    ui->actionRun->setEnabled(false);
    ui->actionStop->setEnabled(false);

    connect(ui->actionRun, &QAction::triggered, this, [=](){
        int res = capture();
        // 捕获正常工作且pointer不为空，开启线程
        if(res != -1 && device_pointer){
            thread->setPointer(device_pointer);
            thread->setFlag();
            thread->start();
            // 按下run后，run设置为不可点击，stop设置为可点击
            ui->actionRun->setEnabled(false);
            ui->actionStop->setEnabled(true);
            ui->comboBox->setEnabled(false);
        }

    });
    connect(ui->actionStop, &QAction::triggered, this, [=](){
        thread->resetFlag();
        thread->quit();
        thread->wait();
        pcap_close(device_pointer);
        device_pointer = nullptr;
        ui->actionStop->setEnabled(false);
        ui->actionRun->setEnabled(true);
        ui->comboBox->setEnabled(true);
    });

    connect(thread, &multhread::getPkt_data, this, &MainWindow::pkt_dataHandler);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showAdapter(){
    int n = pcap_findalldevs(&alldevices, errbuf); //发现所有适配器
    if(n == -1){
        ui->comboBox->addItem("error: " + QString(errbuf));
    }else{
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose an adapter:");
        for (device = alldevices; device; device = device->next){
            QString device_description = device->description;

            ui->comboBox->addItem(device_description);
        }
    }
}

void MainWindow::pkt_dataHandler(dataPacket packet){
//    etherHandler(packet);
    u_short netProtocol = packet.getNetProtocol();
    // switch-case语句里面不能定义变量
    bool flag = true;
    u_char offset = 14;
    u_char offset1 = 0;
    u_char offset2 = 0;
    u_char transProtocol = 0;
    switch (netProtocol){
    // IPv4
    case 0x0800:
        // 设置源地址
        packet.setSAddr(packet.getIpv4SAddr(offset));
        // 设置目的地址
        packet.setDAddr(packet.getIpv4DAddr(offset));
        transProtocol = packet.getIpv4Protocol(offset);
        switch (transProtocol){
        case 6:
            offset1 = offset + packet.getIPv4Hlen(offset);
            packet.setProtocol("TCP");
            packet.setInfo(QString::number(packet.getTcpSport(offset1)));
            packet.setInfo("->");
            packet.setInfo(QString::number(packet.getTcpDport(offset1)));
            packet.setInfo(", len=");
            // 设置包中数据长度，等于ip数据包长度减去ip首部长度再减去tcp首部长度
            packet.setInfo(QString::number(packet.getIPv4Tlen(offset)-packet.getIPv4Hlen(offset)-(packet.getTcpHlen_keep_stat(offset1)>>12)*4));
            break;
        case 17:
            offset2 = offset + packet.getIPv4Hlen(offset);
            packet.setProtocol("UDP");
            packet.setInfo(QString::number(packet.getUdpSport(offset2)));
            packet.setInfo("->");
            packet.setInfo(QString::number(packet.getTcpDport(offset2)));
            packet.setInfo(", len=");
            // 设置包中数据长度，等于ip数据包长度减去ip首部长度再减去tcp首部长度
            packet.setInfo(QString::number(packet.getUdpLen(offset2)));
            break;
        default:
            flag = false;
            break;
        }
        break;

////    // IPv6
////    case 0x86DD:
////        u_char offset = 14;

////        break;
////    // ARP
////    case 0x0806:
////        packet.setProtocol("ARP");
////        arpHandler(packet, 14);
////        break;
    // Don't care
    default:
        flag = false;
        break;
    }

    if(flag){
        ui->tableWidget->insertRow(counterNum);
        ui->tableWidget->setItem(counterNum,0,new QTableWidgetItem(QString::number(counterNum + 1)));
        ui->tableWidget->setItem(counterNum,1,new QTableWidgetItem(packet.getTime()));
        ui->tableWidget->setItem(counterNum,2,new QTableWidgetItem(packet.getSAddr()));
        ui->tableWidget->setItem(counterNum,3,new QTableWidgetItem(packet.getDAddr()));
        ui->tableWidget->setItem(counterNum,4,new QTableWidgetItem(packet.getProtocol()));
        ui->tableWidget->setItem(counterNum,5,new QTableWidgetItem(QString::number(packet.getLength())));
        ui->tableWidget->setItem(counterNum,6,new QTableWidgetItem(packet.getInfo()));
        counterNum++;
    }


}

void MainWindow::on_comboBox_currentIndexChanged(int index){
    int i = 0;
    if(index == 0){
        ui->actionRun->setEnabled(false);
    }

    if(index != 0){
        ui->actionRun->setEnabled(true); // 选择一个适配器后，run按钮设置为可按下
        device = alldevices;
        while(i++ < index-1){
            device = device->next;
        }
    }
    return;
}

int MainWindow::capture(){
    if(device){
        device_pointer = pcap_open_live(device->name, 65536, 1, 1000, errbuf); // 1表示混杂模式
    }else{
         return -1;
    }
    if(!device_pointer){
        pcap_freealldevs(alldevices);
        return -1;
    }else{
        if(pcap_datalink(device_pointer) != DLT_EN10MB){
            pcap_close(device_pointer);
            pcap_freealldevs(alldevices);
            device = nullptr;
            device_pointer = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->description);
    }
    return 0;
}

void MainWindow::etherHandler(dataPacket &packet){
    qDebug() << packet.getTime();
    qDebug() << "len=" << packet.getLength();

    qDebug() << "sMac:" << packet.getSMacAddr();
    qDebug() << "dMAc:" << packet.getDMacAddr();
    u_short netProtocol = packet.getNetProtocol();
    qDebug() << "netProtocol:" << netProtocol;

    switch (netProtocol){
    // IPv4
    case 0x0800:
        ipV4Handler(packet, 14);
        break;
    // IPv6
    case 0x86DD:
        ipV6Handler(packet, 14);
        break;
    // ARP
    case 0x0806:
        packet.setProtocol("ARP");
        arpHandler(packet, 14);
        break;
    // Don't care
    default:
        break;
    }
    qDebug() << "protocol:" << packet.getProtocol();
    qDebug() << "--------------------------------------------";
}

void MainWindow::ipV4Handler(dataPacket &packet, u_char offset){
    qDebug() << "version:" << packet.getIPv4Ver(offset);
    qDebug() << "HeaderLen:" << packet.getIPv4Hlen(offset);
    qDebug() << "tos:" << packet.getIPv4Tos(offset);
    qDebug() << "tlen:" << packet.getIPv4Tlen(offset);
    qDebug() << "identification:" << packet.getIpv4Identification(offset);
    qDebug() << "flags:" << packet.getIpv4Flags(offset);
    qDebug() << "offset" << packet.getIpv4Offset(offset);
    qDebug() << "ttl:" << packet.getIpv4Ttl(offset);
    qDebug() << "transProtocol:" << packet.getIpv4Protocol(offset);
    qDebug() << "crc:" << packet.getIpv4Crc(offset);
    qDebug() << "sAddr:" << packet.getIpv4SAddr(offset);
    qDebug() << "dAddr:" << packet.getIpv4DAddr(offset);

    // 14字节的数据链路层首部和网络层首部长度的和为运输层首部的偏移量
    u_char offset1 = packet.getIPv4Hlen(offset)+14;
    u_char transProtocol = packet.getIpv4Protocol(offset);
    switch (transProtocol){
    case 6:
        packet.setProtocol("TCP");
        tcpHandler(packet, offset1);
        break;
    case 17:
        packet.setProtocol("UDP");
        udpHandler(packet, offset1);
        break;
    }

}


void MainWindow::ipV6Handler(dataPacket &packet, u_char offset){

}

void MainWindow::arpHandler(dataPacket &packet, u_char offset){

}

void MainWindow::tcpHandler(dataPacket &packet, u_char offset){
    qDebug() << "sPort:" << packet.getTcpSport(offset);
    qDebug() << "dPort:" << packet.getTcpDport(offset);
    qDebug() << "seq:" << packet.getTcpSeq(offset);
    qDebug() << "ack:" << packet.getTcpAck(offset);
    u_short tcpHlen_keep_stat = packet.getTcpHlen_keep_stat(offset);
    qDebug() << "hlen:" << (tcpHlen_keep_stat>>12)*4;
    qDebug() << "keep:" << ((tcpHlen_keep_stat>>6)&0x3F);
    u_char stat = tcpHlen_keep_stat&0x3F;
    qDebug() << "URG:" << (stat>>5);
    qDebug() << "ACK:" << ((stat>>4)&0x1);
    qDebug() << "PSH:" << ((stat>>3)&0x1);
    qDebug() << "RST:" << ((stat>>2)&0x1);
    qDebug() << "SYN:" << ((stat>>1)&0x1);
    qDebug() << "FIN:" << (stat&0x1);
    qDebug() << "winSize:" << packet.getTcpWinsize(offset);
    qDebug() << "checkSum:" << packet.getTcpChecksum(offset);
    qDebug() << "urg_ptr:" << packet.getTcpUrg_ptr(offset);
}

void MainWindow::udpHandler(dataPacket &packet, u_char offset){
    qDebug() << "sPort:" << packet.getUdpSport(offset);
    qDebug() << "dPort:" << packet.getUdpDport(offset);
    qDebug() << "len:" << packet.getUdpLen(offset);
}





