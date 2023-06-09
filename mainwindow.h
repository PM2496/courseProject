#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define WIN32
#include <QMainWindow>
#include "pcap.h"
#include "winsock2.h"
#include "datapacket.h"
#include <QString>
#include <QVector>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void showAdapter();
    int capture();
    void ipV4Handler(dataPacket &packet, u_char offset);
    void ipV6Handler(dataPacket &packet, u_char offset);
    void arpHandler(dataPacket &packet, u_char offset);
    void etherHandler(dataPacket &packet);
    void tcpHandler(dataPacket &packet, u_char offset);
    void udpHandler(dataPacket &packet, u_char offset);
public slots:
    void pkt_dataHandler(dataPacket packet);
    void parseData(int row, int clumn);
private slots:
    void on_comboBox_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;
    pcap_if_t * alldevices;
    pcap_if_t * device;
    pcap_t * device_pointer;
//    pcap_dumper_t * dumpfile; // 文件保存
    QString tempFilePath; // 临时文件路径
//    fileHandler * fHandler; // 文件管理
    QVector<dataPacket> datas; // 储存数据
    u_int counterNum; // 记录有效捕获条数
    int mode; // 1表示混杂模式， 0表示非混杂模式
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // MAINWINDOW_H
