#ifndef ANALYZER_H
#define ANALYZER_H

#include <QObject>
#include <QTime>
#include <QDebug>
#include <QByteArray>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef enum _ENCRYPTION
{
    _IEEE80211_ENCRYPT_WPA2WPA,
    _IEEE80211_ENCRYPT_WPA2,
    _IEEE80211_ENCRYPT_WPA,
    _IEEE80211_ENCRYPT_WEP,
    _IEEE80211_NON_ENCRYPT,
} ENCRYPTION;

#pragma pack(push, 1)
struct ieee80211_mgt_infomation
{
    u_int8_t mgt_ie;
    u_int8_t mgt_len;
    u_int8_t mgt_data[0];
};

struct ieee80211_mgt_vendor_infomation
{
    u_int8_t vendor_ie;
    u_int8_t vendor_len;
    u_int32_t vendor_oui:24;
    u_int8_t vendor_oui_type;
    u_int8_t vendor_data[0];
};

struct ieee80211_logical_link_control
{
#define IEEE80211_LINK_CODE_ETH 0x000000
#define IEEE80211_LINK_TYPE_IP 0x0008
    u_int8_t link_dsap;
    u_int8_t link_ssap;
    u_int8_t link_control_field;
    u_int32_t link_orgenization_code:24;
    u_int16_t link_type;
};

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
    QString _uri;
    QString _host;
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
    QString u6byteToQString(u_int8_t* srcId);
    bool isHttpRequest(QString& http, QString& uri);
    bool findHost(QString& http, QString& host);
    bool findCookie(QString& http, QString& cookies);

signals:
    void captured(PACKET_INFOMATION);
    void captureError();

public slots:
    void doStart();
    void doStop() { threadStatu = false; }
};

#endif // ANALYZER_H
