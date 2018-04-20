#define WIN32_LEAN_AND_MEAN
#include <windows.h>
//------------------------------------
// for Winsock
#include <winsock2.h>
#include <ws2tcpip.h>
//------------------------------------
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>
#include "WinPcapWrapper.h"
#include "util.h"

extern "C" {

///////////////////////////////////////////////////////////////////////////////////
// 定数
///////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////
// pcap_stats
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapStatsGetPsRecv)
{
    struct pcap_stat *pcapStat;
    FREResult res;
    FREObject frePsRecv = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(pcapStat->ps_recv, &frePsRecv);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePsRecv;
}

WINPCAP_FRE_FUNC(pcapStatsGetPsDrop)
{
    struct pcap_stat *pcapStat;
    FREResult res;
    FREObject frePsDrop = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(pcapStat->ps_drop, &frePsDrop);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePsDrop;
}

WINPCAP_FRE_FUNC(pcapStatsGetPsIfdrop)
{
    struct pcap_stat *pcapStat;
    FREResult res;
    FREObject frePsIfdrop = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(pcapStat->ps_ifdrop, &frePsIfdrop);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePsIfdrop;
}

WINPCAP_FRE_FUNC(pcapStatsGetPsCapt)
{
    struct pcap_stat *pcapStat;
    FREResult res;
    FREObject frePsCapt = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(pcapStat->ps_capt, &frePsCapt);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePsCapt;
}

WINPCAP_FRE_FUNC(pcapStatsGetPsSent)
{
    struct pcap_stat *pcapStat;
    FREResult res;
    FREObject frePsSent = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(pcapStat->ps_sent, &frePsSent);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePsSent;
}

WINPCAP_FRE_FUNC(pcapStatsGetPsNetdrop)
{
    struct pcap_stat *pcapStat;
    FREResult res;
    FREObject frePsNetdrop = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(pcapStat->ps_netdrop, &frePsNetdrop);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePsNetdrop;
}

} // extern "C"
