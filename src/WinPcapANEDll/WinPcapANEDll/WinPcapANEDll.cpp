#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "WinPcapANEDll.h"
#include "WinPcapWrapper.h"

extern "C" {

////////////////////////////////////////////////////////////////
// ネイティブ拡張I/F
////////////////////////////////////////////////////////////////
static FRENamedFunction functions[] = {
    // name, funcData, function
    {(const uint8_t *)"pcapIfGetNext", NULL, &pcapIfGetNext},
    {(const uint8_t *)"pcapIfGetName", NULL, &pcapIfGetName},
    {(const uint8_t *)"pcapIfGetDescription", NULL, &pcapIfGetDescription},
    {(const uint8_t *)"pcapIfGetAddresses", NULL, &pcapIfGetAddresses},
    {(const uint8_t *)"pcapIfGetFlags", NULL, &pcapIfGetFlags},
    {(const uint8_t *)"pcapAddrGetNext", NULL, &pcapAddrGetNext},
    {(const uint8_t *)"pcapAddrGetAddr", NULL, &pcapAddrGetAddr},
    {(const uint8_t *)"pcapAddrGetNetMask", NULL, &pcapAddrGetNetMask},
    {(const uint8_t *)"pcapAddrGetBroadAddr", NULL, &pcapAddrGetBroadAddr},
    {(const uint8_t *)"pcapAddrGetDstAddr", NULL, &pcapAddrGetDstAddr},
    {(const uint8_t *)"Ntohl", NULL, &Ntohl},
    {(const uint8_t *)"Ntohs", NULL, &Ntohs},
    {(const uint8_t *)"Htonl", NULL, &Htonl},
    {(const uint8_t *)"Htons", NULL, &Htons},
    {(const uint8_t *)"IpAddrByteArrayToString", NULL, &IpAddrByteArrayToString},
    {(const uint8_t *)"IpAddrStringToByteArray", NULL, &IpAddrStringToByteArray},
    {(const uint8_t *)"sockAddrGetSaFamily", NULL, &sockAddrGetSaFamily},
    {(const uint8_t *)"sockAddrGetSaData", NULL, &sockAddrGetSaData},
    {(const uint8_t *)"sockAddrInGetSinFamily", NULL, &sockAddrInGetSinFamily},
    {(const uint8_t *)"sockAddrInGetSinPort", NULL, &sockAddrInGetSinPort},
    {(const uint8_t *)"sockAddrInGetSinAddrAsByteArray", NULL, &sockAddrInGetSinAddrAsByteArray},
    {(const uint8_t *)"sockAddrInGetSinAddrAsUint32", NULL, &sockAddrInGetSinAddrAsUint32},
    {(const uint8_t *)"sockAddrInGetSinAddrAsString", NULL, &sockAddrInGetSinAddrAsString},
    {(const uint8_t *)"sockAddrIn6GetSin6Family", NULL, &sockAddrIn6GetSin6Family},
    {(const uint8_t *)"sockAddrIn6GetSin6Port", NULL, &sockAddrIn6GetSin6Port},
    {(const uint8_t *)"sockAddrIn6GetSin6FlowInfo", NULL, &sockAddrIn6GetSin6FlowInfo},
    {(const uint8_t *)"sockAddrIn6GetSin6AddrAsByteArray", NULL, &sockAddrIn6GetSin6AddrAsByteArray},
    {(const uint8_t *)"sockAddrIn6GetSin6AddrAsUint16Array", NULL, &sockAddrIn6GetSin6AddrAsUint16Array},
    {(const uint8_t *)"sockAddrIn6GetSin6AddrAsString", NULL, &sockAddrIn6GetSin6AddrAsString},
    {(const uint8_t *)"sockAddrIn6GetSin6ScopeId", NULL, &sockAddrIn6GetSin6ScopeId},
    {(const uint8_t *)"pcapPktHdrGetTs", NULL, &pcapPktHdrGetTs},
    {(const uint8_t *)"pcapPktHdrGetCapLen", NULL, &pcapPktHdrGetCapLen},
    {(const uint8_t *)"pcapPktHdrGetLen", NULL, &pcapPktHdrGetLen},
    {(const uint8_t *)"newPcapPktHdr", NULL, &newPcapPktHdr},
    {(const uint8_t *)"freePcapPktHdr", NULL, &freePcapPktHdr},
    {(const uint8_t *)"pcapPktHdrSetCapLen", NULL, &pcapPktHdrSetCapLen},
    {(const uint8_t *)"pcapPktHdrSetLen", NULL, &pcapPktHdrSetLen},
    {(const uint8_t *)"timevalGetTvSec", NULL, &timevalGetTvSec},
    {(const uint8_t *)"timevalGetTvUsec", NULL, &timevalGetTvUsec},
    {(const uint8_t *)"timevalSetTvSec", NULL, &timevalSetTvSec},
    {(const uint8_t *)"timevalSetTvUsec", NULL, &timevalSetTvUsec},
    {(const uint8_t *)"pcapStatsGetPsRecv", NULL, &pcapStatsGetPsRecv},
    {(const uint8_t *)"pcapStatsGetPsDrop", NULL, &pcapStatsGetPsDrop},
    {(const uint8_t *)"pcapStatsGetPsIfdrop", NULL, &pcapStatsGetPsIfdrop},
    {(const uint8_t *)"pcapStatsGetPsCapt", NULL, &pcapStatsGetPsCapt},
    {(const uint8_t *)"pcapStatsGetPsSent", NULL, &pcapStatsGetPsSent},
    {(const uint8_t *)"pcapStatsGetPsNetdrop", NULL, &pcapStatsGetPsNetdrop},
    {(const uint8_t *)"pcapSendQueueGetMaxLen", NULL, &pcapSendQueueGetMaxLen},
    {(const uint8_t *)"pcapSendQueueGetLen", NULL, &pcapSendQueueGetLen},
    {(const uint8_t *)"pcapSendQueueGetBuffer", NULL, &pcapSendQueueGetBuffer},

    // PcapCaptureThread
    {(const uint8_t *)"arrivalPacketListLength", NULL, &arrivalPacketListLength},
    {(const uint8_t *)"arrivalPacketListShift", NULL, &arrivalPacketListShift},
    {(const uint8_t *)"arrivalPacketFree", NULL, &arrivalPacketFree},
    {(const uint8_t *)"arrivalPacketGetPktHdr", NULL, &arrivalPacketGetPktHdr},
    {(const uint8_t *)"arrivalPacketGetPktData", NULL, &arrivalPacketGetPktData},
    {(const uint8_t *)"arrivalPacketGetHandlerRet", NULL, &arrivalPacketGetHandlerRet},
    {(const uint8_t *)"startCaptureThread", NULL, &startCaptureThread},
    {(const uint8_t *)"stopCaptureThread", NULL, &stopCaptureThread},

    // WinPcap exported functions
    {(const uint8_t *)"pcapLibVersion", NULL, &pcapLibVersion},
    {(const uint8_t *)"pcapMajorVersion", NULL, &pcapMajorVersion},
    {(const uint8_t *)"pcapMinorVersion", NULL, &pcapMinorVersion},
    {(const uint8_t *)"pcapGetErr", NULL, &pcapGetErr},
    {(const uint8_t *)"pcapStrError", NULL, &pcapStrError},
    {(const uint8_t *)"pcapFindAllDevs", NULL, &pcapFindAllDevs},
    {(const uint8_t *)"pcapFindAllDevsEx", NULL, &pcapFindAllDevsEx},
    {(const uint8_t *)"pcapFreeAllDevs", NULL, &pcapFreeAllDevs},
    {(const uint8_t *)"pcapCreateSrcStr", NULL, &pcapCreateSrcStr},
    {(const uint8_t *)"pcapParseSrcStr", NULL, &pcapParseSrcStr},
    {(const uint8_t *)"pcapOpen", NULL, &pcapOpen},
    {(const uint8_t *)"pcapClose", NULL, &pcapClose},
    {(const uint8_t *)"pcapNextEx", NULL, &pcapNextEx},
    {(const uint8_t *)"pcapDumpOpen", NULL, &pcapDumpOpen},
    {(const uint8_t *)"pcapDumpClose", NULL, &pcapDumpClose},
    {(const uint8_t *)"pcapDump", NULL, &pcapDump},
    {(const uint8_t *)"pcapDumpFlush", NULL, &pcapDumpFlush},
    {(const uint8_t *)"pcapDumpFTell", NULL, &pcapDumpFTell},
    {(const uint8_t *)"pcapDataLink", NULL, &pcapDataLink},
    {(const uint8_t *)"pcapListDataLinks", NULL, &pcapListDataLinks},
    {(const uint8_t *)"pcapSetDataLink", NULL, &pcapSetDataLink},
    {(const uint8_t *)"pcapDataLinkNameToVal", NULL, &pcapDataLinkNameToVal},
    {(const uint8_t *)"pcapDataLinkValToDescription", NULL, &pcapDataLinkValToDescription},
    {(const uint8_t *)"pcapDataLinkValToName", NULL, &pcapDataLinkValToName},
    {(const uint8_t *)"pcapSetMode", NULL, &pcapSetMode},
    {(const uint8_t *)"pcapSetFilter", NULL, &pcapSetFilter},
    {(const uint8_t *)"pcapStats", NULL, &pcapStats},
    {(const uint8_t *)"pcapSendPacket", NULL, &pcapSendPacket},
    {(const uint8_t *)"pcapSendQueueAlloc", NULL, &pcapSendQueueAlloc},
    {(const uint8_t *)"pcapSendQueueDestroy", NULL, &pcapSendQueueDestroy},
    {(const uint8_t *)"pcapSendQueueQueue", NULL, &pcapSendQueueQueue},
    {(const uint8_t *)"pcapSendQueueTransmit", NULL, &pcapSendQueueTransmit},
};

// ネイティブ拡張コンテキストの初期化関数
static void ContextInitializer(
    void *extData,
    const uint8_t *ctxType,
    FREContext ctx,
    uint32_t *numFunctionsToTest,
    const FRENamedFunction **functionsToSet
    )
{
    *numFunctionsToTest = sizeof(functions)/sizeof(FRENamedFunction);
    *functionsToSet = functions;
}

// ネイティブ拡張コンテキストの破棄関数
static void ContextFinalizer(FREContext ctx)
{
    return;
}

// ネイティブ拡張の初期化関数
WINPCAPANEDLL_API void ExtInitializer(
    void **extDataToSet,
    FREContextInitializer *ctxInitializerToSet,
    FREContextFinalizer *ctxFinalizerToSet
    )
{
    *extDataToSet = NULL;
    *ctxInitializerToSet = &ContextInitializer;
    *ctxFinalizerToSet = &ContextFinalizer;
}

// ネイティブ拡張の破棄関数
WINPCAPANEDLL_API void ExtFinalizer(void *extData)
{
    return;
}

} // extern "C"