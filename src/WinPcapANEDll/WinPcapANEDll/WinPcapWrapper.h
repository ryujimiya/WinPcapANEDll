#ifndef __WINPCAPWRAPPER_H__
#define __WINPCAPWRAPPER_H__
#include <FlashRuntimeExtensions.h>

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////////
// 定義
///////////////////////////////////////////////////////////////////////////////////
#define WINPCAP_FRE_FUNC(func) \
FREObject func(\
    FREContext ctx,\
    void *funcData,\
    uint32_t argc,\
    FREObject arg[]\
    )

///////////////////////////////////////////////////////////////////////////////////
// 定数
///////////////////////////////////////////////////////////////////////////////////
#define MAX_BUF_SIZE (1024)

///////////////////////////////////////////////////////////////////////////////////
// pcap_if
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapIfGetNext);
WINPCAP_FRE_FUNC(pcapIfGetName);
WINPCAP_FRE_FUNC(pcapIfGetDescription);
WINPCAP_FRE_FUNC(pcapIfGetAddresses);
WINPCAP_FRE_FUNC(pcapIfGetFlags);

///////////////////////////////////////////////////////////////////////////////////
// pcap_addr
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapAddrGetNext);
WINPCAP_FRE_FUNC(pcapAddrGetAddr);
WINPCAP_FRE_FUNC(pcapAddrGetNetMask);
WINPCAP_FRE_FUNC(pcapAddrGetBroadAddr);
WINPCAP_FRE_FUNC(pcapAddrGetDstAddr);

///////////////////////////////////////////////////////////////////////////////////
// network/host byte order
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(Ntohl);
WINPCAP_FRE_FUNC(Ntohs);
WINPCAP_FRE_FUNC(Htonl);
WINPCAP_FRE_FUNC(Htons);
WINPCAP_FRE_FUNC(IpAddrByteArrayToString);
WINPCAP_FRE_FUNC(IpAddrStringToByteArray);

///////////////////////////////////////////////////////////////////////////////////
// sockaddr 
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(sockAddrGetSaFamily);
WINPCAP_FRE_FUNC(sockAddrGetSaData);

///////////////////////////////////////////////////////////////////////////////////
// sockaddr_in 
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(sockAddrInGetSinFamily);
WINPCAP_FRE_FUNC(sockAddrInGetSinPort);
WINPCAP_FRE_FUNC(sockAddrInGetSinAddrAsByteArray);
WINPCAP_FRE_FUNC(sockAddrInGetSinAddrAsUint32);
WINPCAP_FRE_FUNC(sockAddrInGetSinAddrAsString);

///////////////////////////////////////////////////////////////////////////////////
// sockaddr_in6 
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6Family);
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6Port);
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6FlowInfo);
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6AddrAsByteArray);
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6AddrAsUint16Array);
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6AddrAsString);
WINPCAP_FRE_FUNC(sockAddrIn6GetSin6ScopeId);

///////////////////////////////////////////////////////////////////////////////////
// pcap_pkthdr
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapPktHdrGetTs);
WINPCAP_FRE_FUNC(pcapPktHdrGetCapLen);
WINPCAP_FRE_FUNC(pcapPktHdrGetLen);
WINPCAP_FRE_FUNC(newPcapPktHdr);
WINPCAP_FRE_FUNC(freePcapPktHdr);
WINPCAP_FRE_FUNC(pcapPktHdrSetCapLen);
WINPCAP_FRE_FUNC(pcapPktHdrSetLen);

///////////////////////////////////////////////////////////////////////////////////
// timeval
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(timevalGetTvSec);
WINPCAP_FRE_FUNC(timevalGetTvUsec);
WINPCAP_FRE_FUNC(timevalSetTvSec);
WINPCAP_FRE_FUNC(timevalSetTvUsec);

///////////////////////////////////////////////////////////////////////////////////
// pcap_stats
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapStatsGetPsRecv);
WINPCAP_FRE_FUNC(pcapStatsGetPsDrop);
WINPCAP_FRE_FUNC(pcapStatsGetPsIfdrop);
WINPCAP_FRE_FUNC(pcapStatsGetPsCapt);
WINPCAP_FRE_FUNC(pcapStatsGetPsSent);
WINPCAP_FRE_FUNC(pcapStatsGetPsNetdrop);

///////////////////////////////////////////////////////////////////////////////////
// pcap_send_queue
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapSendQueueGetMaxLen);
WINPCAP_FRE_FUNC(pcapSendQueueGetLen);
WINPCAP_FRE_FUNC(pcapSendQueueGetBuffer);

///////////////////////////////////////////////////////////////////////////////////
// PcapCaptureThread
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(arrivalPacketListLength);
WINPCAP_FRE_FUNC(arrivalPacketListShift);
WINPCAP_FRE_FUNC(arrivalPacketFree);
WINPCAP_FRE_FUNC(arrivalPacketGetPktHdr);
WINPCAP_FRE_FUNC(arrivalPacketGetPktData);
WINPCAP_FRE_FUNC(arrivalPacketGetHandlerRet);
WINPCAP_FRE_FUNC(startCaptureThread);
WINPCAP_FRE_FUNC(stopCaptureThread);

///////////////////////////////////////////////////////////////////////////////////
// WinPcap exported functions
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapLibVersion);
WINPCAP_FRE_FUNC(pcapMajorVersion);
WINPCAP_FRE_FUNC(pcapMinorVersion);
WINPCAP_FRE_FUNC(pcapGetErr);
WINPCAP_FRE_FUNC(pcapStrError);

WINPCAP_FRE_FUNC(pcapFindAllDevs);
WINPCAP_FRE_FUNC(pcapFindAllDevsEx);
WINPCAP_FRE_FUNC(pcapFreeAllDevs);

WINPCAP_FRE_FUNC(pcapCreateSrcStr);
WINPCAP_FRE_FUNC(pcapParseSrcStr);

WINPCAP_FRE_FUNC(pcapOpen);
WINPCAP_FRE_FUNC(pcapClose);
WINPCAP_FRE_FUNC(pcapNextEx);

WINPCAP_FRE_FUNC(pcapDumpOpen);
WINPCAP_FRE_FUNC(pcapDumpClose);
WINPCAP_FRE_FUNC(pcapDump);
WINPCAP_FRE_FUNC(pcapDumpFlush);
WINPCAP_FRE_FUNC(pcapDumpFTell);

WINPCAP_FRE_FUNC(pcapDataLink);
WINPCAP_FRE_FUNC(pcapListDataLinks);
WINPCAP_FRE_FUNC(pcapSetDataLink);
WINPCAP_FRE_FUNC(pcapDataLinkNameToVal);
WINPCAP_FRE_FUNC(pcapDataLinkValToDescription);
WINPCAP_FRE_FUNC(pcapDataLinkValToName);
WINPCAP_FRE_FUNC(pcapSetMode);
WINPCAP_FRE_FUNC(pcapSetFilter);
WINPCAP_FRE_FUNC(pcapStats);

WINPCAP_FRE_FUNC(pcapSendPacket);
WINPCAP_FRE_FUNC(pcapSendQueueAlloc);
WINPCAP_FRE_FUNC(pcapSendQueueDestroy);
WINPCAP_FRE_FUNC(pcapSendQueueQueue);
WINPCAP_FRE_FUNC(pcapSendQueueTransmit);

#ifdef __cplusplus
} // extern "C"
#endif

#endif