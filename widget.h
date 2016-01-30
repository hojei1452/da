#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QThread>
#include <QObject>
#include <QTreeWidgetItem>
#include <QList>

#include "devselectdlg.h"
#include "analyzer.h"

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private slots:
    void on_pushButton_2_clicked();
    void on_pushButton_clicked();
    void setTreewidget(PACKET_INFOMATION pkt_data);

private:
    Ui::Widget *ui;

    Analyzer analyzer;
    QThread analyzerThread;
};

#endif // WIDGET_H
