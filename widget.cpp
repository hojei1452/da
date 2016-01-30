#include "widget.h"
#include "ui_widget.h"


Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);

    QObject::connect(&analyzerThread, SIGNAL(started()), &analyzer, SLOT(doStart()));
    QObject::connect(&analyzerThread, SIGNAL(finished()), &analyzer, SLOT(doStop()));

    QObject::connect(&analyzer, SIGNAL(captured(PACKET_INFOMATION)), this, SLOT(setTreewidget(PACKET_INFOMATION)), Qt::BlockingQueuedConnection);
    QObject::connect(&analyzer, SIGNAL(captureError()), &analyzerThread, SLOT(quit()));
}

Widget::~Widget()
{
    delete ui;
}

void Widget::on_pushButton_2_clicked()
{
    DevSelectDlg deviceOpen;
    deviceOpen.show();
    deviceOpen.exec();

    analyzer.moveToThread(&analyzerThread);
    analyzer.setHandle(deviceOpen.devhandle);
    analyzer.threadStatu = true;
    analyzerThread.start();
    ui->label->setText("Running");
}

void Widget::on_pushButton_clicked()
{
    analyzer.threadStatu = false;
    analyzerThread.quit();
    analyzerThread.wait();
    ui->label->setText("Stopped");
}

void Widget::setTreewidget(PACKET_INFOMATION pkt_data)
{
    if(pkt_data._ap_infomation._bssid == NULL)
        return;

    QList<QTreeWidgetItem*> listItem = ui->treeWidget->findItems(pkt_data._ap_infomation._bssid, Qt::MatchWildcard, 1);
    if(listItem.count() == 0)   // new AP
    {
        if(pkt_data._ap_infomation._ssid == NULL)
            return;

        QTreeWidgetItem* newItem = new QTreeWidgetItem(ui->treeWidget);
        newItem->setText(0, pkt_data._ap_infomation._ssid);
        newItem->setText(1, pkt_data._ap_infomation._bssid);
        if(pkt_data._ap_infomation._enc == _IEEE80211_ENCRYPT_WPA2)
            newItem->setText(2, QString("WPA2"));
        else if(pkt_data._ap_infomation._enc == _IEEE80211_ENCRYPT_WPA)
            newItem->setText(2, QString("WPA"));
        else if(pkt_data._ap_infomation._enc == _IEEE80211_ENCRYPT_WPA2WPA)
            newItem->setText(2, QString("WPA/WPA2"));
        else if(pkt_data._ap_infomation._enc == _IEEE80211_ENCRYPT_WEP)
            newItem->setText(2, QString("WEP"));
        else if(pkt_data._ap_infomation._enc == _IEEE80211_NON_ENCRYPT)
            newItem->setText(2, QString("OPEN"));

        newItem->setText(3, QString::number(0));
    }
    else if(listItem.count() == 1)
    {
        if(pkt_data._station_infomation._data == NULL || pkt_data._station_infomation._stationid == NULL)
            return;

        QTreeWidgetItem* currentItem = listItem[0];
        QList<QTreeWidgetItem*> listItems = ui->treeWidget->findItems(pkt_data._station_infomation._stationid, Qt::MatchExactly | Qt::MatchRecursive, 1);
        if(listItems.count() == 0)  // new station
        {
            QTreeWidgetItem* items = new QTreeWidgetItem(currentItem);
            items->setText(0, QString("Station"));
            items->setText(1, pkt_data._station_infomation._stationid);

            items = new QTreeWidgetItem(items);
            items->setText(0, QString("info"));

            QTreeWidgetItem* infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("HOST"));
            infos->setText(1, pkt_data._station_infomation._host);
            infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("URI"));
            infos->setText(1, pkt_data._station_infomation._uri);
            infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("COOKIE"));
            infos->setText(1, pkt_data._station_infomation._cookie);
            infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("TIME"));
            infos->setText(1, pkt_data._station_infomation._currentTime.toString());
        }
        else if(listItems.count() == 1)
        {
            QTreeWidgetItem* items = new QTreeWidgetItem(listItems[0]);
            items->setText(0, QString("info"));

            QTreeWidgetItem* infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("HOST"));
            infos->setText(1, pkt_data._station_infomation._host);
            infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("URI"));
            infos->setText(1, pkt_data._station_infomation._uri);
            infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("COOKIE"));
            infos->setText(1, pkt_data._station_infomation._cookie);
            infos = new QTreeWidgetItem(items);
            infos->setText(0, QString("TIME"));
            infos->setText(1, pkt_data._station_infomation._currentTime.toString());
        }
    }
}














