#ifndef DEVSELECTDLG_H
#define DEVSELECTDLG_H

#include <QDialog>
#include <QMessageBox>
#include <QDebug>
#include <QListWidgetItem>
#include <pcap.h>
#include <QPushButton>

#define PCAP_READABLE_SIZE 65536
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_OPENFLAG_NON_PROMISCUOUS 0

namespace Ui {
class DevSelectDlg;
}

class DevSelectDlg : public QDialog
{
    Q_OBJECT

public:
    explicit DevSelectDlg(QWidget *parent = 0);
    ~DevSelectDlg();

    pcap_t* devhandle;
    QString confingName;

private:
    Ui::DevSelectDlg *ui;

    pcap_if_t* alldevs;
    pcap_if_t* devsTmp;
    char errbuf[PCAP_ERRBUF_SIZE];

protected:
    void showallDev();
    void choiceDev();

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);
};

#endif // DEVSELECTDLG_H
