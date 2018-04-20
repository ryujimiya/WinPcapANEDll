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
// ’è”
///////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////
// pcap_send_queue
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(pcapSendQueueGetMaxLen)
{
    struct pcap_send_queue *queue;
    FREResult res;
    FREObject freMaxLen = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&queue);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(queue->maxlen, &freMaxLen);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freMaxLen;
}

WINPCAP_FRE_FUNC(pcapSendQueueGetLen)
{
    struct pcap_send_queue *queue;
    FREResult res;
    FREObject freLen = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&queue);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32(queue->len, &freLen);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freLen;
}

WINPCAP_FRE_FUNC(pcapSendQueueGetBuffer)
{
    struct pcap_send_queue *queue;
    FREResult res;
    int len;
    char *buffer;
    FREObject freBuffer = NULL;
    FREObject length = NULL;
    FREByteArray byteArray;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&queue);
    if (res != FRE_OK)
    {
        return NULL;
    }

    len = queue->len;
    buffer = queue->buffer;

    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &freBuffer, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(len, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(freBuffer, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (len > 0)
    {
        res = FREAcquireByteArray(freBuffer, &byteArray);
        if (res != FRE_OK)
        {
            return NULL;
        }
        memcpy(byteArray.bytes, buffer, len);
        res = FREReleaseByteArray(freBuffer);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    return freBuffer;
}

} // extern "C"