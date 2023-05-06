#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <string>
#include <QDebug>
#include <QStringList>
#include <QMessageBox>
#include <QFileDialog>
#include <QColor>
#include "multhread.h"
#include "packetHeader.h"
#include <windows.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    counterNum = 0;

//    qDebug() << filePath;
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
        // 如果counterNum大于0，需要询问是否保存数据
        if(counterNum > 0){
            QMessageBox::StandardButton reply;
            reply = QMessageBox::question(this, "Unsaved packets",
                                          "您是否要在开始新捕获前保存已捕获的分组？\n若不保存，您已经捕获的分组将会丢失",

                                          QMessageBox::Yes | QMessageBox::No |QMessageBox::Cancel);
            // 选择cancel什么也不做
            if(reply == QMessageBox::Cancel){
                return;
            }
            // 选择yes开始保存，保存后清空所有数据并重新开始捕获
            else if(reply == QMessageBox::Yes){
                QString filePath = QFileDialog::getSaveFileName(this, "save", "./", "pcap files(*.pcap)");

                WCHAR sour[100], dest[100];
                memset(sour, 0, sizeof(sour));
                memset(dest, 0, sizeof(dest));
                char * f1 = tempFilePath.toLatin1().data();
                char * f2 = filePath.toLatin1().data();
                MultiByteToWideChar(CP_ACP, 0, f1, strlen(f1)+1, sour, sizeof(sour)/sizeof(sour[0]));
                MultiByteToWideChar(CP_ACP, 0, f2, strlen(f2)+1, dest, sizeof(dest)/sizeof(dest[0]));
                qDebug() << tempFilePath;
                qDebug() << filePath;
                CopyFile(sour, dest, false);//FALSE:如果目标位置已经存在同名文件，就覆盖，return 1
                                            //TRUE:如果目标位置已经存在同名文件，则补拷贝，return 0
                                            //后者路径若不错在，return 0
                remove(tempFilePath.toLatin1().data());

                datas.clear();
                counterNum = 0;
                ui->tableWidget->setRowCount(1);
                ui->tableWidget->clearContents();
                ui->treeWidget->clear();
            }
            // 选择NO就直接清空所有数据并重新开始捕获
            else if(reply == QMessageBox::No){
                remove(tempFilePath.toLatin1().data());
                datas.clear();
                counterNum = 0;
                ui->tableWidget->setRowCount(1);
                ui->tableWidget->clearContents();
                ui->treeWidget->clear();
//                widgets[index-1].setRowCount(0)
//                widgets[index-1].clearContents()
            }
        }
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
//        dumpfile = thread->getDumpfile();
        tempFilePath = thread->getFilePath();
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
//    u_char offset2 = 0;
    u_char transProtocol = 0;
    u_short opCode;
    QColor color;
    u_char * tcpData = nullptr; // 用于判断是否为http协议
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

            // 判断是否为http
            tcpData = packet.getTcpOption(offset1)+(packet.getTcpHlen_keep_stat(offset1)>>12)*4-20; // tcp选项指针字段加上选项长度等于tcp数据指针字段
            if ((char(*tcpData) == 'G' && char(*(tcpData+1)) == 'E' && char(*(tcpData+2)) == 'T')
                    || (char(*tcpData) == 'P' && char(*(tcpData+1)) == 'O' && char(*(tcpData+2)) == 'S' && char(*(tcpData+3)) == 'T')
                    || (char(*tcpData) == 'H' && char(*(tcpData+1)) == 'T' && char(*(tcpData+2)) == 'T' && char(*(tcpData+3)) == 'P')){
                packet.setProtocol("HTTP");
                color = QColor(27, 93, 221);
            }
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
        offset1 = offset + 40; // ipv6头部长度为40字节，这里不考虑扩展头部长度

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

            // 判断是否为http
            tcpData = packet.getTcpOption(offset1)+(packet.getTcpHlen_keep_stat(offset1)>>12)*4-20; // tcp选项指针字段加上选项长度等于tcp数据指针字段
            if (char(*tcpData) == 'H' && char(*(tcpData+1)) == 'T' && char(*(tcpData+2) == 'T' && char(*(tcpData+3)) == 'P')){
                packet.setProtocol("HTTP");
                color = QColor(27, 93, 221);
            }
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
    // switch case语句里面不能定义变量
    u_char offset = 14;
    u_char offset1 = 0;
//    u_char offset2 = 0;

    QTreeWidgetItem * item0;
    QTreeWidgetItem * UdpData;
    QTreeWidgetItem * flagTree;
    QTreeWidgetItem * TcpOption;
//    QTreeWidgetItem * TcpData;
    u_char transProtocol = 0;
    u_short tcpHlen_keep_stat = 0;
    u_char tcpOptionLength = 0; // tcp option字段长度
    u_char * tcpOption = nullptr; // tcp option字段指针
    u_char * tcpData = nullptr; // tcp数据字段指针
    QString httpHeader = "";
    // tcp option字段各选项
    u_char kind = 0;
    u_char length = 0;
//    u_char * info = nullptr;
    // tcp flag字段
    u_char stat = 0;

    u_short netProtocol = datas[row].getNetProtocol();
    switch(netProtocol){
    case 0x0806:
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type: ARP "));
        item0 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol");
        ui->treeWidget->addTopLevelItem(item0);
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type: "+datas[row].getArpHType(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type: "+datas[row].getArpProType(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size: "+QString::number(datas[row].getArpHSize(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size: "+QString::number(datas[row].getArpProSize(offset))));
        if(datas[row].getArpOpCode(offset) == 1){
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Opcode: request (1)"));
        }
        else if(datas[row].getArpOpCode(offset) == 2){
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Opcode: reply (2)"));
        }
        else{
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Opcode: "+QString::number(datas[row].getArpOpCode(offset))));
        }

        item0->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address: "+datas[row].getArpSMacAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address: "+datas[row].getArpSAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address: "+datas[row].getArpDMacAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address: "+datas[row].getArpDAddr(offset)));

        break;
    case 0x0800:
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type: IPv4"));
        item0 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4");
        ui->treeWidget->addTopLevelItem(item0);
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Version: 4"));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: "+QString::number(datas[row].getIPv4Hlen(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Tos: "+QString::number(datas[row].getIPv4Tos(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:"+QString::number(datas[row].getIPv4Tlen(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Identification: "+QString::number(datas[row].getIpv4Identification(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Flags: "+QString::number(datas[row].getIpv4Flags(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset: "+QString::number(datas[row].getIpv4Offset(offset))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live: "+QString::number(datas[row].getIpv4Ttl(offset))));
        transProtocol = datas[row].getIpv4Protocol(offset);
        switch (transProtocol){
        case 6:
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: TCP"));
            break;
        case 17:
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: UDP"));
            break;
        default:
            break;
        }
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Header CheckSum: "+QString::number((datas[row].getIpv4Crc(offset)))));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Source Address: "+datas[row].getIpv4SAddr(offset)));
        item0->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address: "+datas[row].getIpv4DAddr(offset)));
        offset1 = offset + datas[row].getIPv4Hlen(offset);
        switch (transProtocol){
        case 6:
            item0 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol");
            ui->treeWidget->addTopLevelItem(item0);
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: "+QString::number(datas[row].getTcpSport(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:"+QString::number(datas[row].getTcpDport(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: "+QString::number(datas[row].getTcpSeq(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgement Number: "+QString::number(datas[row].getTcpAck(offset1))));
            tcpHlen_keep_stat = datas[row].getTcpHlen_keep_stat(offset1);
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: "+QString::number((tcpHlen_keep_stat>>12)*4)));

            flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" );
            item0->addChild(flagTree);
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"Keeped: "+QString::number((tcpHlen_keep_stat>>6)&0x3F)));
            stat = tcpHlen_keep_stat&0x3F;
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"URG:"+QString::number((stat>>5))));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"ACK:"+QString::number((stat>>4)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"PSH:"+QString::number((stat>>3)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"RST:"+QString::number((stat>>2)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"SYN:"+QString::number((stat>>1)&0x1)));
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<"FIN:"+QString::number(stat&0x1)));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"WinSize: "+QString::number(datas[row].getTcpWinsize(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"CheckSum: "+QString::number(datas[row].getTcpChecksum(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer: "+QString::number(datas[row].getTcpUrg_ptr(offset1))));
            tcpOptionLength = (tcpHlen_keep_stat>>12)*4 - 20; //头部长度减去固定20字节，得到选项字段长度
            if (tcpOptionLength != 0){
                item0 = new QTreeWidgetItem(QStringList()<<"Options");
                ui->treeWidget->addTopLevelItem(item0);
                while(tcpOptionLength){
                    tcpOption = datas[row].getTcpOption(offset1);
                    kind = *tcpOption;
                    TcpOption = new QTreeWidgetItem(QStringList()<<"TCP Option");
                    item0->addChild(TcpOption);
                    if (kind == 0){
                        length = 1;

                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Kind: EOL"));
                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Length: 1"));
                    }
                    else if(kind == 1){
                        length = 1;

                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Kind: NOP"));
                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Length: 1"));
                    }
                    else if(kind == 2){
                        length = 4;

                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Kind: MSS"));
                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Length: 4"));
                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"MSS Value: "+QString::number(ntohs(*(u_short *)(tcpOption+2)))));
                    }else{
                        kind = *tcpOption;
                        length = *(tcpOption+1);

                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Kind: "+QString::number(kind)));
                        TcpOption->addChild(new QTreeWidgetItem(QStringList()<<"Length: "+QString::number(kind)));

                    }
                    tcpOptionLength -= length;
                    tcpOption += length;
                }
            }
            tcpData = datas[row].getTcpOption(offset1)+tcpOptionLength; // tcp选项字段指针加上选项字段长度，得到tcp数据字段指针
            // 如果数据字段以GET或POST或HTTP开头，我们就认为是http协议
            if ((char(*tcpData) == 'G' && char(*(tcpData+1)) == 'E' && char(*(tcpData+2)) == 'T')
                    || (char(*tcpData) == 'P' && char(*(tcpData+1)) == 'O' && char(*(tcpData+2)) == 'S' && char(*(tcpData+3)) == 'T')
                    || (char(*tcpData) == 'H' && char(*(tcpData+1)) == 'T' && char(*(tcpData+2)) == 'T' && char(*(tcpData+3)) == 'P')){
                item0 = new QTreeWidgetItem(QStringList()<<"Hypertext Transfer Protocol");
                ui->treeWidget->addTopLevelItem(item0);
                while (true){
                    if (*tcpData == 0x0d && *(tcpData+1) == 0x0a){
                        if(*(tcpData+2) == 0x0d && *(tcpData+3) == 0x0a) break;
                        item0->addChild(new QTreeWidgetItem(QStringList()<<httpHeader));
                        httpHeader = "";
                        tcpData += 2;
                        continue;
                    }
                    httpHeader += char(*tcpData);
                    tcpData += 1;
                }
            }
            break;
        case 17:
            item0= new QTreeWidgetItem(QStringList()<<"User Datagram Protocol");
            ui->treeWidget->addTopLevelItem(item0);
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: "+QString::number(datas[row].getUdpSport(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: "+QString::number(datas[row].getUdpDport(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Length: "+QString::number(datas[row].getUdpLen(offset1))));
            item0->addChild(new QTreeWidgetItem(QStringList()<<"Checksum: "+datas[row].getUdpCheckSum(offset1)));

            if(datas[row].getUdpLen(offset1)>8){
                UdpData = new QTreeWidgetItem(QStringList()<<"Data ("+QString::number(datas[row].getUdpLen(offset1)-8)+" bytes)");
                ui->treeWidget->addTopLevelItem(UdpData);

                UdpData->addChild(new QTreeWidgetItem(QStringList()<<"data: "+datas[row].getUdpData(offset1)));
            }

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

