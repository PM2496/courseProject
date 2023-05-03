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
    mode = 1; // 默认为混杂模式
    // 设置file相关选项，刚开始保存选项无法点击
    ui->actionSave->setEnabled(false);
    datas.clear(); // 数据清空
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(40); // 设置高度
    QStringList title = {"NO.", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);

    ui->tableWidget->setColumnWidth(0, 75);
    ui->tableWidget->setColumnWidth(1, 150);
    ui->tableWidget->setColumnWidth(2, 300);
    ui->tableWidget->setColumnWidth(3, 300);
    ui->tableWidget->setColumnWidth(4, 150);
    ui->tableWidget->setColumnWidth(5, 100);
    ui->tableWidget->setColumnWidth(6, 1000);

    // 设置表头宽度自适应
//    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    ui->tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows); // 设置整行选中
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers); // 设置不可编辑


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
            // 按下run后，open、save、run设置为不可点击，stop设置为可点击，模式不可更改
            ui->actionOpen->setEnabled(false);
            ui->actionSave->setEnabled(false);
            ui->actionRun->setEnabled(false);
            ui->actionStop->setEnabled(true);
            ui->comboBox->setEnabled(false);
            ui->menuMode->setEnabled(false);
        }

    });
    connect(ui->actionStop, &QAction::triggered, this, [=](){
        thread->resetFlag();
        thread->quit();
        thread->wait();
        pcap_close(device_pointer);
        device_pointer = nullptr;
        // 更新按钮状态
        ui->actionOpen->setEnabled(true);
        ui->actionSave->setEnabled(true);
        ui->actionStop->setEnabled(false);
        ui->actionRun->setEnabled(true);
        ui->comboBox->setEnabled(true);
        ui->menuMode->setEnabled(true);
    });
    // 切换为混杂模式
    connect(ui->actionPromiscuous, &QAction::triggered, this, [=](){
        mode = 1;
        ui->actionPromiscuous->setEnabled(false);
        ui->actionDirect->setEnabled(true);
    });
    // 切换为直接模式
    connect(ui->actionDirect, &QAction::triggered, this, [=](){
        mode = 0;
        ui->actionDirect->setEnabled(false);
        ui->actionPromiscuous->setEnabled(true);
    });
    // 开启新线程处理数据
    connect(thread, &multhread::getPkt_data, this, &MainWindow::pkt_dataHandler);

    // 点击行元素触发解析事件
    connect(ui->tableWidget, &QTableWidget::cellClicked, this, &MainWindow::parseData);

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
    u_short opCode;
    QColor color;
    switch (netProtocol){
    // ARP
    case 0x0806:
        packet.setSAddr(packet.getArpSMacAddr(offset));
        packet.setProtocol("ARP");
        color = QColor(218, 221, 27);
        opCode = packet.getArpOpCode(offset);
        // ARP请求
        if (opCode == 1){
            packet.setDAddr("Broadcast");
            packet.setInfo("Who has ");
            packet.setInfo(packet.getArpDAddr(offset));
            packet.setInfo("? Tell ");
            packet.setInfo(packet.getArpSAddr(offset));
        }
        // ARP应答
        else if(opCode == 2){
            packet.setDAddr(packet.getArpDMacAddr(offset));
            packet.setInfo(packet.getArpSAddr(offset));
            packet.setInfo(" is at ");
            packet.setInfo(packet.getArpSMacAddr(offset));
        }

        break;
    // IPv4
    case 0x0800:
        // 设置源地址
        packet.setSAddr(packet.getIpv4SAddr(offset));
        // 设置目的地址
        packet.setDAddr(packet.getIpv4DAddr(offset));
        transProtocol = packet.getIpv4Protocol(offset);
        offset1 = offset + packet.getIPv4Hlen(offset);
        switch (transProtocol){
        case 6:
            packet.setProtocol("TCP");
            color = QColor(216,191,216);
            packet.setInfo(QString::number(packet.getTcpSport(offset1)));
            packet.setInfo("->");
            packet.setInfo(QString::number(packet.getTcpDport(offset1)));
            packet.setInfo(", len=");
            // 设置包中数据长度，等于ip数据包长度减去ip首部长度再减去tcp首部长度
            packet.setInfo(QString::number(packet.getIPv4Tlen(offset)-packet.getIPv4Hlen(offset)-(packet.getTcpHlen_keep_stat(offset1)>>12)*4));
            break;
        case 17:
            packet.setProtocol("UDP");
            color = QColor(144,238,144);
            packet.setInfo(QString::number(packet.getUdpSport(offset1)));
            packet.setInfo("->");
            packet.setInfo(QString::number(packet.getTcpDport(offset1)));
            packet.setInfo(", len=");
            // 设置包中数据长度，等于ip数据包长度减去ip首部长度再减去tcp首部长度
            packet.setInfo(QString::number(packet.getUdpLen(offset1)));
            break;
        default:
            flag = false;
            break;
        }
        break;

        // IPv6
    case 0x86DD:
        // 设置源地址
        packet.setSAddr(packet.getIpv6SAddr(offset));
        // 设置目的地址
        packet.setDAddr(packet.getIpv6DAddr(offset));
        transProtocol = packet.getIpv6NextHeader(offset);
        offset1 = offset + 40; // ipv6头部长度为40字节
        switch (transProtocol){
        case 6:
            packet.setProtocol("TCP");
            color = QColor(216,191,216);
            packet.setInfo(QString::number(packet.getTcpSport(offset1)));
            packet.setInfo("->");
            packet.setInfo(QString::number(packet.getTcpDport(offset1)));
            packet.setInfo(", len=");
            // 设置包中数据长度，等于ipv6有效载荷数据包长度减去tcp首部长度
            packet.setInfo(QString::number(packet.getIpv6Len(offset)-(packet.getTcpHlen_keep_stat(offset1)>>12)*4));
            break;
        case 17:
            packet.setProtocol("UDP");
            color = QColor(144,238,144);
            packet.setInfo(QString::number(packet.getUdpSport(offset1)));
            packet.setInfo("->");
            packet.setInfo(QString::number(packet.getTcpDport(offset1)));
            packet.setInfo(", len=");
            // 设置包中数据长度，等于ip数据包长度减去ip首部长度再减去tcp首部长度
            packet.setInfo(QString::number(packet.getUdpLen(offset1)));
            break;
        default:
            flag = false;
            break;
        }
        break;

    default:
        flag = false;
        break;
    }

    if(flag){
        datas.push_back(packet);
        ui->tableWidget->insertRow(counterNum);
        ui->tableWidget->setItem(counterNum,0,new QTableWidgetItem(QString::number(counterNum + 1)));
        ui->tableWidget->setItem(counterNum,1,new QTableWidgetItem(packet.getTime()));
        ui->tableWidget->setItem(counterNum,2,new QTableWidgetItem(packet.getSAddr()));
        ui->tableWidget->setItem(counterNum,3,new QTableWidgetItem(packet.getDAddr()));
        ui->tableWidget->setItem(counterNum,4,new QTableWidgetItem(packet.getProtocol()));
        ui->tableWidget->setItem(counterNum,5,new QTableWidgetItem(QString::number(packet.getLength())));
        ui->tableWidget->setItem(counterNum,6,new QTableWidgetItem(packet.getInfo()));
        for(int i = 0;i < 7;i++){
            ui->tableWidget->item(counterNum,i)->setBackground(color);
        }
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
//        qDebug() << mode;
        device_pointer = pcap_open_live(device->name, 65536, mode, 1000, errbuf); // mode为1表示混杂模式
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

void MainWindow::parseData(int row, int clumn){
//    qDebug() << "row = " << row << ", clumn = " << clumn;
//    qDebug() << datas[row].getSAddr();
    ui->treeWidget->clear();
    QTreeWidgetItem * item = new QTreeWidgetItem(QStringList()<<"Ethernet");
    ui->treeWidget->addTopLevelItem(item);
    item->addChild(new QTreeWidgetItem(QStringList()<<"Source: "+datas[row].getSMacAddr()));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Destination: "+datas[row].getDMacAddr()));
    u_char offset = 14;
    u_char offset1 = 0;
    u_char offset2 = 0;
    QTreeWidgetItem * item0;
    QTreeWidgetItem * item1;
    QTreeWidgetItem * item2;
    QTreeWidgetItem * item3;
    QTreeWidgetItem * flagTree;
    u_char transProtocol = 0;
    u_short tcpHlen_keep_stat = 0;
    u_char stat = 0;
    u_short netProtocol = datas[row].getNetProtocol();
    switch(netProtocol){
    case 0x0806:
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type: ARP"));
        item0 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol");
        ui->treeWidget->addTopLevelItem(item0);
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:"+datas[row].getArpHType(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:"+datas[row].getArpProType(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:"+QString::number(datas[row].getArpHSize(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:"+QString::number(datas[row].getArpProSize(offset))));
        if(datas[row].getArpOpCode(offset) == 1){
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:request (1)"));
        }
        else if(datas[row].getArpOpCode(offset) == 2){
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:reply (2)"));
        }
        else{
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:"+QString::number(datas[row].getArpOpCode(offset))));
        }

        item0->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:"+datas[row].getArpSMacAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:"+datas[row].getArpSAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:"+datas[row].getArpDMacAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:"+datas[row].getArpDAddr(offset)));

        break;
    case 0x0800:
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type: IPv4"));
        item1 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4");
        ui->treeWidget->addTopLevelItem(item1);
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Version: 4"));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: "+QString::number(datas[row].getIPv4Hlen(offset))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Tos: "+QString::number(datas[row].getIPv4Tos(offset))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:"+QString::number(datas[row].getIPv4Tlen(offset))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Identification: "+QString::number(datas[row].getIpv4Identification(offset))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Flags: "+QString::number(datas[row].getIpv4Flags(offset))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset: "+QString::number(datas[row].getIpv4Offset(offset))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live: "+QString::number(datas[row].getIpv4Ttl(offset))));
        transProtocol = datas[row].getIpv4Protocol(offset);
        switch (transProtocol){
        case 6:
            item1->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: TCP"));
            break;
        case 17:
            item1->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: UDP"));
            break;
        default:
            break;
        }
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Header CheckSum: "+QString::number((datas[row].getIpv4Crc(offset)))));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Source Address: "+datas[row].getIpv4SAddr(offset)));
        item1->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address: "+datas[row].getIpv4DAddr(offset)));
        offset1 = offset + datas[row].getIPv4Hlen(offset);
        switch (transProtocol){
        case 6:
            item2 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol");
            ui->treeWidget->addTopLevelItem(item2);
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: "+QString::number(datas[row].getTcpSport(offset1))));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:"+QString::number(datas[row].getTcpDport(offset1))));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: "+QString::number(datas[row].getTcpSeq(offset1))));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgement Number: "+QString::number(datas[row].getTcpAck(offset1))));
            tcpHlen_keep_stat = datas[row].getTcpHlen_keep_stat(offset1);
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: "+QString::number((tcpHlen_keep_stat>>12)*4)));

            flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" );
            item2->addChild(flagTree);
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"Keeped: "+QString::number((tcpHlen_keep_stat>>6)&0x3F)));
            stat = tcpHlen_keep_stat&0x3F;
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"URG:"+QString::number((stat>>5))));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"ACK:"+QString::number((stat>>4)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"PSH:"+QString::number((stat>>3)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"RST:"+QString::number((stat>>2)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"SYN:"+QString::number((stat>>1)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"FIN:"+QString::number(stat&0x1)));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"WinSize: "+QString::number(datas[row].getTcpWinsize(offset1))));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"CheckSum: "+QString::number(datas[row].getTcpChecksum(offset1))));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer: "+QString::number(datas[row].getTcpUrg_ptr(offset1))));

            break;
        case 17:
            item3= new QTreeWidgetItem(QStringList()<<"User Datagram Protocol");
            ui->treeWidget->addTopLevelItem(item3);
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: "+QString::number(datas[row].getUdpSport(offset1))));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: "+QString::number(datas[row].getUdpDport(offset1))));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Length: "+QString::number(datas[row].getUdpLen(offset1))));
            break;
        default:
            break;
        }
        break;
    case 0x86DD:
        item->addChild(new QTreeWidgetItem(QStringList()<<"IPv6"));
        break;
    default:
        break;
    }
}

