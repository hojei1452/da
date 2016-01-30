#include "analyzer.h"
#include "ieee80211.h"
#include "ieee80211_radiotap.h"

Analyzer::Analyzer(QObject *parent) : QObject(parent)
{

}

void Analyzer::doStart()
{
    while(threadStatu)
    {
        pcap_pkthdr* header;
        const u_char* pkt_data;

        int res = pcap_next_ex(handle, &header, &pkt_data);
        if(res == 0)
            continue;
        else if(res < 0)
            break;

        PACKET_INFOMATION packetInfo;

        int dataPointer = 0;

        ieee80211_radiotap_header* pRadiotap = (struct ieee80211_radiotap_header*)pkt_data;
        dataPointer += pRadiotap->it_len;

        ieee80211_frame* pFrame = (struct ieee80211_frame*)(pkt_data + dataPointer);
        u_int8_t frameType = pFrame->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        u_int8_t frameSubtype = pFrame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        if(frameType == IEEE80211_FC0_TYPE_MGT
                && (frameSubtype == IEEE80211_FC0_SUBTYPE_BEACON || frameSubtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP))
        {
            packetInfo._ap_infomation._bssid = u6byteToQString(pFrame->i_addr3);
            dataPointer += sizeof(struct ieee80211_frame);

            ieee80211_mgt_beacon_t mgtBeacon = (u_int8_t*)(pkt_data + dataPointer);
            u_int16_t beacon_capability = IEEE80211_BEACON_CAPABILITY(mgtBeacon);
            if(beacon_capability & IEEE80211_CAPINFO_PRIVACY)
                packetInfo._ap_infomation._enc = _IEEE80211_ENCRYPT_WEP;
            else
                packetInfo._ap_infomation._enc = _IEEE80211_NON_ENCRYPT;
            dataPointer += (sizeof(u_int8_t) * 12); // fixed parameters size 12byte

            ieee80211_mgt_infomation* infomation;
            do{
                infomation = (struct ieee80211_mgt_infomation*)(pkt_data + dataPointer);
                if((infomation->mgt_len + dataPointer) > (int)header->len)
                    break;

                if(infomation->mgt_ie == IEEE80211_ELEMID_SSID && infomation->mgt_len != 0)
                {
                    QByteArray ba((const char *)(pkt_data + dataPointer + 2), infomation->mgt_len);
                    QString ssid(ba);
                    packetInfo._ap_infomation._ssid = ssid;
                }
                else if(infomation->mgt_ie == IEEE80211_ELEMID_RSN)
                {
                    if(packetInfo._ap_infomation._enc == _IEEE80211_ENCRYPT_WPA)
                        packetInfo._ap_infomation._enc = _IEEE80211_ENCRYPT_WPA2WPA;
                    else
                        packetInfo._ap_infomation._enc = _IEEE80211_ENCRYPT_WPA2;
                }
                else if(infomation->mgt_ie == IEEE80211_ELEMID_VENDOR)
                {
                    ieee80211_mgt_vendor_infomation* vendor_Infomation = (struct ieee80211_mgt_vendor_infomation*)(pkt_data + dataPointer);
                    if(vendor_Infomation->vendor_oui == WPA_OUI && vendor_Infomation->vendor_oui_type == WPA_OUI_TYPE)
                    {
                        if(packetInfo._ap_infomation._enc == _IEEE80211_ENCRYPT_WPA2)
                            packetInfo._ap_infomation._enc = _IEEE80211_ENCRYPT_WPA2WPA;
                        else
                            packetInfo._ap_infomation._enc = _IEEE80211_ENCRYPT_WPA;
                    }
                }

                if(infomation->mgt_len != 0)
                    dataPointer += (int)infomation->mgt_len;
                dataPointer += sizeof(u_int8_t);   // infomation->mgt_ie size u_int8_t(1)
                dataPointer += sizeof(u_int8_t);   // infomation->mgt_len  size u_int8_t(1)
            } while(dataPointer < (int)header->len);
        }
        else if(frameType == IEEE80211_FC0_TYPE_DATA
                && frameSubtype == IEEE80211_FC0_SUBTYPE_QOS)
        {
            ieee80211_qosframe* pQosFrame = (struct ieee80211_qosframe*)(pkt_data + dataPointer);
            u_int8_t dsStatus = pQosFrame->i_fc[1] & IEEE80211_FC1_DIR_MASK;
            if(dsStatus == IEEE80211_FC1_DIR_FROMDS)
            {
                packetInfo._ap_infomation._bssid = u6byteToQString(pQosFrame->i_addr2);
                packetInfo._station_infomation._stationid = u6byteToQString(pQosFrame->i_addr1);
            }
            else if(dsStatus == IEEE80211_FC1_DIR_TODS)
            {
                packetInfo._ap_infomation._bssid = u6byteToQString(pQosFrame->i_addr1);
                packetInfo._station_infomation._stationid = u6byteToQString(pQosFrame->i_addr2);
            }
            else
                continue;

            dataPointer += sizeof(struct ieee80211_qosframe);

            //if(isOpenModeAP(packetInfo._ap_infomation._bssid))
            //  continue;

            ieee80211_logical_link_control* plinkControl = (struct ieee80211_logical_link_control*)(pkt_data + dataPointer);
            if(plinkControl->link_type == IEEE80211_LINK_TYPE_IP && plinkControl->link_orgenization_code == IEEE80211_LINK_CODE_ETH)
            {
                dataPointer += sizeof(struct ieee80211_logical_link_control);

                iphdr* ip_ = (struct iphdr*)(pkt_data + dataPointer);
                if(ip_->protocol == IPPROTO_TCP)
                {
                    dataPointer += (ip_->ihl * 4);

                    tcphdr* tcp_ = (struct tcphdr*)(pkt_data + dataPointer);
                    dataPointer += (tcp_->th_off * 4);
                    int dataLen = (int)header->len - dataPointer;
                    if(dataLen == 0)    // no data
                        continue;
                    QByteArray ba((const char *)(pkt_data + dataPointer), dataLen);
                    QString data(ba);
                    packetInfo._station_infomation._data = data;

                    QString uri;
                    if(!isHttpRequest(data, uri))
                        continue;

                    QString host;
                    if(!findHost(data, host))
                        continue;

                    QString cookie;
                    if(!findCookie(data, cookie))
                        continue;

                    packetInfo._station_infomation._uri = uri;
                    packetInfo._station_infomation._host = host;
                    packetInfo._station_infomation._cookie = cookie;
                    packetInfo._station_infomation._currentTime = QTime::currentTime();
                }
            }

        }
        emit captured(packetInfo);
    }
}

QString Analyzer::u6byteToQString(u_int8_t* srcId)
{
    u_int8_t ch1, ch2;
    int i, index;
    char buf[IEEE80211_ADDR_LEN * 3];

    index = 0;
    for (i = 0; i < IEEE80211_ADDR_LEN; i++)
    {
        ch1 = srcId[i] & 0xF0;
        ch1 = ch1 >> 4;
        if (ch1 > 9)
            ch1 = ch1 + 'A' - 10;
        else
            ch1 = ch1 + '0';
        ch2 = srcId[i] & 0x0F;
        if (ch2 > 9)
            ch2 = ch2 + 'A' - 10;
        else
            ch2 = ch2 + '0';
        buf[index++] = ch1;
        buf[index++] = ch2;
        buf[index++] = ':';
    }
    buf[--index] = '\0';
    return (QString(buf));
}

bool Analyzer::isHttpRequest(QString& http, QString& uri) {
    int i;

    bool res = false;
    if (http.startsWith("GET ")) {
        i = 4;
        res = true;
    }
    else if (http.startsWith("POST ")) {
        i = 5;
        res = true;
    }
    if (!res) return false;

    while (true) {
        if (i >= http.length())
            return false;
        if (http[i] == ' ')
            break;
        uri += http[i];
        i++;
    }
    return true;
}

bool Analyzer::findHost(QString& http, QString& host) {
    static QRegExp rexHost("\r\nHost: ([^\r]*)");
    int i = rexHost.indexIn(http);
    if (i == -1) return false;
    host = rexHost.cap(1);
    return true;
}

bool Analyzer::findCookie(QString& http, QString& cookies) {
    static QRegExp rexCookie("\r\nCookie: ([^\r]*)");
    int i = rexCookie.indexIn(http);
    if (i == -1) return false;
    cookies = rexCookie.cap(1);
    return true;
}
