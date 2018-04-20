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
// pcap_pkthdr
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapPktHdrGetTs)
{
    struct pcap_pkthdr *pcapPktHdr;
    FREResult res;
    FREObject freTs = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(&pcapPktHdr->ts), &freTs);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freTs;
}

WINPCAP_FRE_FUNC(pcapPktHdrGetCapLen)
{
    struct pcap_pkthdr *pcapPktHdr;
    FREResult res;
    FREObject freCapLen = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(pcapPktHdr->caplen), &freCapLen);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freCapLen;
}

WINPCAP_FRE_FUNC(pcapPktHdrGetLen)
{
    struct pcap_pkthdr *pcapPktHdr;
    FREResult res;
    FREObject freLen = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(pcapPktHdr->len), &freLen);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freLen;
}

// for sendqueue
WINPCAP_FRE_FUNC(newPcapPktHdr)
{
    struct pcap_pkthdr *pcapPktHdr;
    FREResult res;
    FREObject frePcapPktHdr = NULL;

    pcapPktHdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    memset(pcapPktHdr, 0, sizeof(struct pcap_pkthdr));

    res = FRENewObjectFromUint32((uint32_t)pcapPktHdr, &frePcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePcapPktHdr;
}

// for sendqueue
WINPCAP_FRE_FUNC(freePcapPktHdr)
{
    struct pcap_pkthdr *pcapPktHdr;
    FREResult res;
    int ret = 0;
    FREObject freRetVal = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    free(pcapPktHdr);

    ret = 0; // 常に成功
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

// for sendqueue
WINPCAP_FRE_FUNC(pcapPktHdrSetCapLen)
{
    struct pcap_pkthdr *pcapPktHdr;
    bpf_u_int32 capLen;
    FREResult res;
    int ret = 0;
    FREObject freRetVal;

    if (argc != 2)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[1], &capLen);
    if (res != FRE_OK)
    {
        return NULL;
    }

    pcapPktHdr->caplen = capLen;

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

// for sendqueue
WINPCAP_FRE_FUNC(pcapPktHdrSetLen)
{
    struct pcap_pkthdr *pcapPktHdr;
    bpf_u_int32 len;
    FREResult res;
    int ret = 0;
    FREObject freRetVal;

    if (argc != 2)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapPktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[1], &len);
    if (res != FRE_OK)
    {
        return NULL;
    }

    pcapPktHdr->len = len;

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

///////////////////////////////////////////////////////////////////////////////////
// timeval
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(timevalGetTvSec)
{
    struct timeval *timevalp;
    FREResult res;
    FREObject freTvSec = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&timevalp);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(timevalp->tv_sec), &freTvSec);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freTvSec;
}

WINPCAP_FRE_FUNC(timevalGetTvUsec)
{
    struct timeval *timevalp;
    FREResult res;
    FREObject freTvUsec = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&timevalp);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(timevalp->tv_usec), &freTvUsec);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freTvUsec;
}

// for sendqueue
WINPCAP_FRE_FUNC(timevalSetTvSec)
{
    struct timeval *timevalp;
    long tvSec;
    FREResult res;
    int ret = 0;
    FREObject freRetVal;

    if (argc != 2)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&timevalp);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&tvSec);
    if (res != FRE_OK)
    {
        return NULL;
    }

    timevalp->tv_sec = tvSec;

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

// for sendqueue
WINPCAP_FRE_FUNC(timevalSetTvUsec)
{
    struct timeval *timevalp;
    long tvUsec;
    FREResult res;
    int ret = 0;
    FREObject freRetVal;

    if (argc != 2)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&timevalp);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&tvUsec);
    if (res != FRE_OK)
    {
        return NULL;
    }

    timevalp->tv_usec = tvUsec;

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

} // extern "C"