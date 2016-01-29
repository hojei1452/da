#include "analyzer.h"

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
    }
}
