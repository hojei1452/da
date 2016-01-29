#ifndef ANALYZER_H
#define ANALYZER_H

#include <QObject>
#include <QTime>
#include <pcap.h>

typedef enum _ENCRYPTION
{
    _IEEE80211_ENCRYPT_WPA2WPA,
    _IEEE80211_ENCRYPT_WPA2,
    _IEEE80211_ENCRYPT_WPA,
    _IEEE80211_ENCRYPT_WEP,
    _IEEE80211_NON_ENCRYPT,
} ENCRYPTION;

#pragma pack(push, 1)
typedef struct _AP_INFOMATION
{
    QString _bssid;
    QString _ssid;
    ENCRYPTION _enc;
} AP_INFOMATION, *LPAP_INFOMATION;

typedef struct _STATION_INFOMATION
{
    QString _stationid;
    QString _data;
    QString _url;
    QString _cookie;
    QTime _currentTime;
} STATION_INFOMATION, *LPSTATION_INFOMATION;

typedef struct _PACKET_INFOMATION
{
    AP_INFOMATION _ap_infomation;
    STATION_INFOMATION _station_infomation;
} PACKET_INFOMATION, LPPACKET_INFOMATION;
#pragma pack(pop)

class Analyzer : public QObject
{
    Q_OBJECT
public:
    explicit Analyzer(QObject *parent = 0);
    void setHandle(pcap_t* handle) { this->handle = handle; }

    bool threadStatu;

private:
    pcap_t* handle;

protected:

signals:
    void captured(PACKET_INFOMATION);
    void captureError();

public slots:
    void doStart();
    void doStop() { threadStatu = false; }
};

#endif // ANALYZER_H
