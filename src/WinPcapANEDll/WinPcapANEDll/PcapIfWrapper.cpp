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
// pcap_if
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapIfGetNext)
{
    struct pcap_if *pcapIf;
    FREResult res;
    FREObject freNext = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapIf);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapIf->next == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapIf->next), &freNext);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freNext;
}

WINPCAP_FRE_FUNC(pcapIfGetName)
{
    struct pcap_if *pcapIf;
    char nameBufUTF8[MAX_BUF_SIZE];
    FREResult res;
    FREObject freName = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapIf);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapIf->name == NULL)
    {
        return NULL;
    }
    _strCpyToUTF8(nameBufUTF8, sizeof(nameBufUTF8), pcapIf->name);
    res = FRENewObjectFromUTF8(strlen(nameBufUTF8), (const uint8_t *)nameBufUTF8, &freName);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freName;
}

WINPCAP_FRE_FUNC(pcapIfGetDescription)
{
    struct pcap_if *pcapIf;
    char descriptionBufUTF8[MAX_BUF_SIZE];
    FREResult res;
    FREObject freDescription = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapIf);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapIf->description == NULL)
    {
        return NULL;
    }
    _strCpyToUTF8(descriptionBufUTF8, sizeof(descriptionBufUTF8), pcapIf->description);
    res = FRENewObjectFromUTF8(strlen(descriptionBufUTF8), (const uint8_t *)descriptionBufUTF8, &freDescription);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freDescription;
}

WINPCAP_FRE_FUNC(pcapIfGetAddresses)
{
    struct pcap_if *pcapIf;
    FREResult res;
    FREObject freAddresses = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapIf);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapIf->addresses == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapIf->addresses), &freAddresses);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freAddresses;
}

WINPCAP_FRE_FUNC(pcapIfGetFlags)
{
    struct pcap_if *pcapIf;
    FREResult res;
    FREObject freFlags = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapIf);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(pcapIf->flags), &freFlags);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freFlags;
}

///////////////////////////////////////////////////////////////////////////////////
// pcap_addr
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapAddrGetNext)
{
    struct pcap_addr *pcapAddr;
    FREResult res;
    FREObject freNext = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapAddr->next == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapAddr->next), &freNext);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freNext;
}

WINPCAP_FRE_FUNC(pcapAddrGetAddr)
{
    struct pcap_addr *pcapAddr;
    FREResult res;
    FREObject freAddr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapAddr->addr == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapAddr->addr), &freAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freAddr;
}

WINPCAP_FRE_FUNC(pcapAddrGetNetMask)
{
    struct pcap_addr *pcapAddr;
    FREResult res;
    FREObject freNetMask = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapAddr->netmask == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapAddr->netmask), &freNetMask);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freNetMask;
}

WINPCAP_FRE_FUNC(pcapAddrGetBroadAddr)
{
    struct pcap_addr *pcapAddr;
    FREResult res;
    FREObject freBroadAddr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapAddr->broadaddr == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapAddr->broadaddr), &freBroadAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freBroadAddr;
}

WINPCAP_FRE_FUNC(pcapAddrGetDstAddr)
{
    struct pcap_addr *pcapAddr;
    FREResult res;
    FREObject freDstAddr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&pcapAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (pcapAddr->dstaddr == NULL)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)(pcapAddr->dstaddr), &freDstAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freDstAddr;
}

///////////////////////////////////////////////////////////////////////////////////
// network/host byte order
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(Ntohl)
{
    FREResult res;
    ULONG netlong;
    ULONG hostlong;
    FREObject freHostLong = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&netlong);
    if (res != FRE_OK)
    {
        return NULL;
    }

    hostlong = ntohl(netlong);

    res = FRENewObjectFromUint32(hostlong, &freHostLong);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freHostLong;
}

WINPCAP_FRE_FUNC(Ntohs)
{
    FREResult res;
    USHORT netshort;
    USHORT hostshort;
    FREObject freHostShort = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&netshort);
    if (res != FRE_OK)
    {
        return NULL;
    }

    hostshort = ntohs(netshort);

    res = FRENewObjectFromUint32(hostshort, &freHostShort);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freHostShort;
}

WINPCAP_FRE_FUNC(Htonl)
{
    FREResult res;
    ULONG hostlong;
    ULONG netlong;
    FREObject freNetLong = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&hostlong);
    if (res != FRE_OK)
    {
        return NULL;
    }

    netlong = htonl(hostlong);

    res = FRENewObjectFromUint32(netlong, &freNetLong);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freNetLong;
}

WINPCAP_FRE_FUNC(Htons)
{
    FREResult res;
    USHORT hostshort;
    USHORT netshort;
    FREObject freNetShort = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&hostshort);
    if (res != FRE_OK)
    {
        return NULL;
    }

    netshort = htons(hostshort);

    res = FRENewObjectFromUint32(netshort, &freNetShort);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freNetShort;
}

WINPCAP_FRE_FUNC(IpAddrByteArrayToString)
{
    FREResult res;
    int family;
    FREObject freAddr;
    FREByteArray byteArray;
    PVOID addrp = NULL;
    IN_ADDR in4Addr;
    IN6_ADDR in6Addr;
    int addrStrLen = 0;
    char addrStr[46];
    wchar_t addrStrUnicode[sizeof(addrStr)];
    FREObject freAddrAsString;

    if (argc != 2)
    {
        return NULL;
    }

    res = FREGetObjectAsInt32(arg[0], &family);
    if (res != FRE_OK)
    {
        return NULL;
    }
    freAddr = arg[1];
    res = FREAcquireByteArray(freAddr, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (family == AF_INET)
    {
        ULONG addrNetLong = *((ULONG *)byteArray.bytes);
        in4Addr.S_un.S_addr = addrNetLong;
        addrp = &in4Addr;
        addrStrLen = 16;
    }
    else if (family == AF_INET6)
    {
        memcpy(in6Addr.u.Byte, byteArray.bytes, byteArray.length);
        //USHORT *addrNetShort = (USHORT *)byteArray.bytes;
        //for (i = 0; i < 8; i++)
        //{
        //    in6Addr.u.Word[i] = addrNetShort[i];
        //}
        addrp = &in6Addr;
        addrStrLen = 46;
    }

    res = FREReleaseByteArray(freAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    if (addrp == NULL)
    {
        return NULL;
    }

    // API
    memset(addrStrUnicode, 0x0, sizeof(addrStrUnicode));
    InetNtop(family, addrp, (PTSTR)addrStrUnicode, addrStrLen);
    UnicodeToUTF8(addrStrUnicode, addrStr, sizeof(addrStr));

    res = FRENewObjectFromUTF8(strlen(addrStr), (const uint8_t *)addrStr, &freAddrAsString);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freAddrAsString;
}

WINPCAP_FRE_FUNC(IpAddrStringToByteArray)
{
    FREResult res;
    int family;
    int addrStrLen;
    char *addrStr;
    wchar_t addrStrUnicode[46];
    int ret;
    PVOID addrp = NULL;
    IN_ADDR in4Addr;
    IN6_ADDR in6Addr;
    unsigned char *addrBytes = NULL;
    int addrBytesLen = 0;
    FREObject freAddr;
    FREObject length;
    FREByteArray byteArray;

    if (argc != 2)
    {
        return NULL;
    }

    res = FREGetObjectAsInt32(arg[0], &family);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUTF8(arg[1], (uint32_t *)&addrStrLen, (const uint8_t **)&addrStr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    UTF8toUnicode(addrStr, addrStrUnicode, sizeof(addrStrUnicode) / sizeof(wchar_t));

    if (family == AF_INET)
    {
        addrp = &in4Addr;
    }
    else if (family == AF_INET6)
    {
        addrp = &in6Addr;
    }

    // API
    ret = InetPton(family, addrStrUnicode, addrp);
    if (ret != 1)
    {
        return NULL;
    }

    if (family == AF_INET)
    {
        ULONG addrNetLong = in4Addr.S_un.S_addr;
        addrBytes = (unsigned char *)&addrNetLong;
        addrBytesLen = 4;
    }
    else if (family == AF_INET6)
    {
        addrBytes = (unsigned char *)in6Addr.u.Byte;
        addrBytesLen = 16;
    }


    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &freAddr, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(addrBytesLen, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(freAddr, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREAcquireByteArray(freAddr, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }
    memcpy(byteArray.bytes, addrBytes, addrBytesLen);
    res = FREReleaseByteArray(freAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    return freAddr;
}

///////////////////////////////////////////////////////////////////////////////////
// sockaddr 
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(sockAddrGetSaFamily)
{
    struct sockaddr *sockAddr;
    FREResult res;
    FREObject freSaFamily = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddr->sa_family), &freSaFamily);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSaFamily;
}

WINPCAP_FRE_FUNC(sockAddrGetSaData)
{
    struct sockaddr *sockAddr;
    int len;
    char *data;
    FREResult res;
    FREObject length;
    FREObject freSaData = NULL;
    FREByteArray byteArray;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }

    len = sizeof(sockAddr->sa_data);
    data = sockAddr->sa_data;
    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &freSaData, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(len, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(freSaData, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREAcquireByteArray(freSaData, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }
    memcpy(byteArray.bytes, data, len);
    res = FREReleaseByteArray(freSaData);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSaData;
}

///////////////////////////////////////////////////////////////////////////////////
// sockaddr_in 
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(sockAddrInGetSinFamily)
{
    SOCKADDR_IN *sockAddrIn;
    FREResult res;
    FREObject freSinFamily = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn->sin_family), &freSinFamily);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSinFamily;
}

WINPCAP_FRE_FUNC(sockAddrInGetSinPort)
{
    SOCKADDR_IN *sockAddrIn;
    FREResult res;
    FREObject freSinPort = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn->sin_port), &freSinPort);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSinPort;
}

WINPCAP_FRE_FUNC(sockAddrInGetSinAddrAsByteArray)
{
    SOCKADDR_IN *sockAddrIn;
    int len;
    char *addr;
    FREResult res;
    FREObject length = NULL;
    FREObject freSinAddr = NULL;
    FREByteArray byteArray;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn);
    if (res != FRE_OK)
    {
        return NULL;
    }

    len = sizeof(sockAddrIn->sin_addr.S_un.S_addr);
    addr = (char *)&sockAddrIn->sin_addr.S_un.S_addr;
    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &freSinAddr, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(len, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(freSinAddr, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREAcquireByteArray(freSinAddr, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }
    memcpy(byteArray.bytes, addr, len);
    res = FREReleaseByteArray(freSinAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSinAddr;
}

WINPCAP_FRE_FUNC(sockAddrInGetSinAddrAsUint32)
{
    SOCKADDR_IN *sockAddrIn;
    FREResult res;
    FREObject freSinAddr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn->sin_addr.S_un.S_addr), &freSinAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSinAddr;
}

WINPCAP_FRE_FUNC(sockAddrInGetSinAddrAsString)
{
    SOCKADDR_IN *sockAddrIn;
    char addrStr[16];
    wchar_t addrStrUnicode[sizeof(addrStr)];
    FREResult res;
    FREObject freSinAddr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn);
    if (res != FRE_OK)
    {
        return NULL;
    }

    memset(addrStrUnicode, 0x0, sizeof(addrStrUnicode));
    InetNtop(AF_INET, &(sockAddrIn->sin_addr), (PTSTR)addrStrUnicode, sizeof(addrStrUnicode)/sizeof(wchar_t));
    UnicodeToUTF8(addrStrUnicode, addrStr, sizeof(addrStr));

    res = FRENewObjectFromUTF8(strlen(addrStr), (const uint8_t *)addrStr, &freSinAddr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSinAddr;
}

///////////////////////////////////////////////////////////////////////////////////
// sockaddr_in6 
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6Family)
{
    SOCKADDR_IN6 *sockAddrIn6;
    FREResult res;
    FREObject freSin6Family = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn6->sin6_family), &freSin6Family);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSin6Family;
}

WINPCAP_FRE_FUNC(sockAddrIn6GetSin6Port)
{
    SOCKADDR_IN6 *sockAddrIn6;
    FREResult res;
    FREObject freSin6Port = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn6->sin6_port), &freSin6Port);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSin6Port;
}

WINPCAP_FRE_FUNC(sockAddrIn6GetSin6FlowInfo)
{
    SOCKADDR_IN6 *sockAddrIn6;
    FREResult res;
    FREObject freSin6FlowInfo = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn6->sin6_flowinfo), &freSin6FlowInfo);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSin6FlowInfo;
}

WINPCAP_FRE_FUNC(sockAddrIn6GetSin6AddrAsByteArray)
{
    SOCKADDR_IN6 *sockAddrIn6;
    int len;
    char *addr;
    FREResult res;
    FREObject length = NULL;
    FREObject freSin6Addr = NULL;
    FREByteArray byteArray;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    len = sizeof(sockAddrIn6->sin6_addr.u.Byte);
    addr = (char *)&sockAddrIn6->sin6_addr.u.Byte[0];
    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &freSin6Addr, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(len, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(freSin6Addr, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREAcquireByteArray(freSin6Addr, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }
    memcpy(byteArray.bytes, addr, len);
    res = FREReleaseByteArray(freSin6Addr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSin6Addr;
}

WINPCAP_FRE_FUNC(sockAddrIn6GetSin6AddrAsUint16Array)
{
    SOCKADDR_IN6 *sockAddrIn6;
    const int len = 8;
    int i;
    FREResult res;
    FREObject value;
    FREObject freSin6Addr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObject((const uint8_t *)"Array", 0, NULL, &freSin6Addr, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    
    }
    res = FRESetArrayLength(freSin6Addr, len);
    if (res != FRE_OK)
    {
        return NULL;
    
    }
    for (i = 0; i < len; i++)
    {
        res = FRENewObjectFromUint32(sockAddrIn6->sin6_addr.u.Word[i], &value);
        if (res != FRE_OK)
        {
            return NULL;
        }
        res = FRESetArrayElementAt(freSin6Addr, i, value);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    return freSin6Addr;
}

WINPCAP_FRE_FUNC(sockAddrIn6GetSin6AddrAsString)
{
    SOCKADDR_IN6 *sockAddrIn6;
    char addrStr[46];
    wchar_t addrStrUnicode[sizeof(addrStr)];
    FREResult res;
    FREObject freSin6Addr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    memset(addrStrUnicode, 0x0, sizeof(addrStrUnicode));
    InetNtop(AF_INET6, &(sockAddrIn6->sin6_addr), (PTSTR)addrStrUnicode, sizeof(addrStrUnicode)/sizeof(wchar_t));
    UnicodeToUTF8(addrStrUnicode, addrStr, sizeof(addrStr));

    res = FRENewObjectFromUTF8(strlen(addrStr), (const uint8_t *)addrStr, &freSin6Addr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSin6Addr;
}

WINPCAP_FRE_FUNC(sockAddrIn6GetSin6ScopeId)
{
    SOCKADDR_IN6 *sockAddrIn6;
    FREResult res;
    FREObject freSin6ScopeId = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&sockAddrIn6);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)(sockAddrIn6->sin6_scope_id), &freSin6ScopeId);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSin6ScopeId;
}


} // extern "C"