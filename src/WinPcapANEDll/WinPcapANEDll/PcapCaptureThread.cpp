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
// ��`
///////////////////////////////////////////////////////////////////////////////////
typedef struct _ArrivalPacket
{
    struct _ArrivalPacket *next;
    struct pcap_pkthdr header;
    u_char *pktData;
    int handlerRet;
}  ArrivalPacket;

typedef struct _CaptureThreadParam
{
    FREContext ctx;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    HANDLE threadHandle;
    ArrivalPacket *arrivalPacketList;
    HANDLE listMutexHandle;
} CaptureThreadParam;

///////////////////////////////////////////////////////////////////////////////////
// �萔
///////////////////////////////////////////////////////////////////////////////////
#define CAPTURETHREAD_PACKETARRIVAL "CAPTURETHREAD_PACKETARRIVAL"
#define CAPTURETHREAD_THREADFUNCFINISHED "CAPTURETHREAD_THREADFUNCFINISHED"

///////////////////////////////////////////////////////////////////////////////////
// �ϐ�
///////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////
// functions
///////////////////////////////////////////////////////////////////////////////////
static ArrivalPacket * newArrivalPacket(const struct pcap_pkthdr *header, const u_char *pktData)
{
    ArrivalPacket *arrivalPacket;
    
    arrivalPacket = (ArrivalPacket *)malloc(sizeof(ArrivalPacket));
    arrivalPacket->next = NULL;
    memcpy(&arrivalPacket->header, header, sizeof(struct pcap_pkthdr));
    if (header->caplen > 0)
    {
        arrivalPacket->pktData = (u_char *)malloc(header->caplen);
        memcpy(arrivalPacket->pktData, pktData, header->caplen);
    }
    else
    {
        arrivalPacket->pktData = NULL;
    }
    arrivalPacket->handlerRet = 0;
    return arrivalPacket;
}

static void freeArrivalPacket(ArrivalPacket *arrivalPacket)
{
    if (arrivalPacket->pktData != NULL)
    {
        free(arrivalPacket->pktData);
        arrivalPacket->pktData = NULL;
    }
    free(arrivalPacket);
}

static ArrivalPacket * ArrivalPacketList_GetLast(ArrivalPacket *list, HANDLE mutexHandle)
{
    ArrivalPacket *cur = NULL;
    ArrivalPacket *last = NULL;
    DWORD waitRet;

    if (mutexHandle != NULL)
    {
        waitRet = WaitForSingleObject(mutexHandle, INFINITE); // lock
        if (waitRet != WAIT_OBJECT_0)
        {
            return last;
        }
    }
    cur = list;
    while (cur != NULL)
    {
        last = cur;
        cur = cur->next;
    }
    if (mutexHandle != NULL)
    {
        ReleaseMutex(mutexHandle); // unlock
    }

    return last;
}

static BOOL ArrivalPacketList_PushBack(ArrivalPacket **listp, ArrivalPacket *arrivalPacket, HANDLE mutexHandle)
{
    ArrivalPacket *last = NULL;
    DWORD waitRet;

    waitRet = WaitForSingleObject(mutexHandle, INFINITE); // lock
    if (waitRet != WAIT_OBJECT_0)
    {
        return FALSE;
    }
    if (*listp == NULL)
    {
        *listp = arrivalPacket;
    }
    else
    {
        last = ArrivalPacketList_GetLast(*listp, NULL); // note: mutexHandle���w�肵�Ȃ�(���Ƀ��b�N�ς݂Ȃ̂�)
        last->next = arrivalPacket;
    }
    ReleaseMutex(mutexHandle); // unlock

    return TRUE;
}

static ArrivalPacket * ArrivalPacketList_Shift(ArrivalPacket **listp, HANDLE mutexHandle)
{
    ArrivalPacket *first = NULL;
    DWORD waitRet;

    waitRet = WaitForSingleObject(mutexHandle, INFINITE); // lock
    if (waitRet != WAIT_OBJECT_0)
    {
        return first;
    }
    first = *listp;
    if (first != NULL)
    {
        *listp = first->next;
        first->next = NULL;
    }
    ReleaseMutex(mutexHandle); // unlock

    return first;
}

static BOOL ArrivalPacketList_RemoveAll(ArrivalPacket **listp, HANDLE mutexHandle)
{
    ArrivalPacket *cur = NULL;
    ArrivalPacket *next = NULL;
    DWORD waitRet;

    waitRet = WaitForSingleObject(mutexHandle, INFINITE); // lock
    if (waitRet != WAIT_OBJECT_0)
    {
        return FALSE;
    }
    cur = *listp;
    while (cur != NULL)
    {
        next = cur->next;
        freeArrivalPacket(cur);
        cur = next;
    }
    *listp = NULL;
    ReleaseMutex(mutexHandle); // unlock

    return TRUE;
}

static int ArrivalPacketList_Length(ArrivalPacket *list, HANDLE mutexHandle)
{
    int packetCnt = 0;
    ArrivalPacket *cur = NULL;
    DWORD waitRet;
    waitRet = WaitForSingleObject(mutexHandle, INFINITE); // lock
    if (waitRet != WAIT_OBJECT_0)
    {
        return FALSE;
    }
    cur = list;
    while (cur != NULL)
    {
        cur = cur->next;
        packetCnt++;
    }
    ReleaseMutex(mutexHandle); // unlock
    return packetCnt;
}

/// <summary>
/// WinPcap�p�P�b�g�n���h��
/// </summary>
/// <param name="param"></param>
/// <param name="header"></param>
/// <param name="pkt_data"></param>
/// <param name="src"></param>
static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    FREResult res;
    const char *code = CAPTURETHREAD_PACKETARRIVAL;
    const char *level = ""; // Note: NULL�ɂ���ƃC�x���g���������Ȃ��̂Œ���
    CaptureThreadParam * captureThreadParam = (CaptureThreadParam *)param;
    HANDLE listMutexHandle = captureThreadParam->listMutexHandle;
    ArrivalPacket *arrivalPacket = NULL;
    BOOL pushbackRet = FALSE;
    int handlerRet = 1; // 1:�p�P�b�g�擾���� -1:�G���[

    arrivalPacket = newArrivalPacket(header, pkt_data);
    pushbackRet = ArrivalPacketList_PushBack(&captureThreadParam->arrivalPacketList, arrivalPacket, listMutexHandle);
    if (!pushbackRet)
    {
        // �ǉ����s
        freeArrivalPacket(arrivalPacket);
        return;
    }
    res = FREDispatchStatusEventAsync(captureThreadParam->ctx, (const uint8_t *)code, (const uint8_t *)level);
    if (res != FRE_OK)
    {
        handlerRet = -1;
    }
    else
    {
        handlerRet = 1; // pcap_next_ex�̖߂�l�ƌ݊�������������
    }
    arrivalPacket->handlerRet = handlerRet;
}

/// <summary>
/// �L���v�`���[�X���b�h����
/// </summary>
/// <param name="param"></param>
/// <param name="src"></param>
static DWORD WINAPI pcapCaptureThreadFunc(LPVOID param)
{
    CaptureThreadParam * captureThreadParam = (CaptureThreadParam *)param;
    FREResult res;
    const char *code = CAPTURETHREAD_THREADFUNCFINISHED;
    const char *level = ""; // Note: NULL�ɂ���ƃC�x���g���������Ȃ��̂Œ���

    // �p�P�b�g�L���v�`���[���[�v
    int ret = pcap_loop(captureThreadParam->pcapHandle, 0, packetHandler, (u_char *)captureThreadParam);

     // �X���b�h�����I���ʒm
    res = FREDispatchStatusEventAsync(captureThreadParam->ctx, (const uint8_t *)code, (const uint8_t *)level);
    if (res != FRE_OK)
    {
        // �G���[
        // ��������
    }

    ExitThread(ret);
}

///////////////////////////////////////////////////////////////////////////////////
// exported functions
///////////////////////////////////////////////////////////////////////////////////
WINPCAP_FRE_FUNC(arrivalPacketListLength)
{
    FREResult res;
    CaptureThreadParam *captureThreadParam;
    int packetCnt = 0;
    FREObject frePacketCnt = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&captureThreadParam);
    if (res != FRE_OK)
    {
        return NULL;
    }
    // 
    packetCnt = ArrivalPacketList_Length(captureThreadParam->arrivalPacketList, captureThreadParam->listMutexHandle);

    res = FRENewObjectFromInt32((int32_t)packetCnt, &frePacketCnt);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePacketCnt;
}

WINPCAP_FRE_FUNC(arrivalPacketListShift)
{
    FREResult res;
    CaptureThreadParam *captureThreadParam;
    ArrivalPacket *arrivalPacket;
    FREObject freArraivalPacket = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&captureThreadParam);
    if (res != FRE_OK)
    {
        return NULL;
    }
    // 
    arrivalPacket = ArrivalPacketList_Shift(&captureThreadParam->arrivalPacketList, captureThreadParam->listMutexHandle);

    res = FRENewObjectFromUint32((uint32_t)arrivalPacket, &freArraivalPacket);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freArraivalPacket;
}

WINPCAP_FRE_FUNC(arrivalPacketFree)
{
    FREResult res;
    ArrivalPacket *arrivalPacket;
    int ret = 0;
    FREObject freRetVal = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&arrivalPacket);
    if (res != FRE_OK)
    {
        return NULL;
    }
    //
    freeArrivalPacket(arrivalPacket);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

WINPCAP_FRE_FUNC(arrivalPacketGetPktHdr)
{
    FREResult res;
    ArrivalPacket *arrivalPacket;
    FREObject frePktHdr = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&arrivalPacket);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromUint32((uint32_t)&arrivalPacket->header, &frePktHdr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePktHdr;
}

WINPCAP_FRE_FUNC(arrivalPacketGetPktData)
{
    FREResult res;
    ArrivalPacket *arrivalPacket;
    int pktDataLen;
    u_char *pktData;
    FREObject frePktData = NULL;
    FREObject length = NULL;
    FREByteArray byteArray;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&arrivalPacket);
    if (res != FRE_OK)
    {
        return NULL;
    }

    pktDataLen = arrivalPacket->header.caplen;
    pktData = arrivalPacket->pktData;

    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &frePktData, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(pktDataLen, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(frePktData, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (pktDataLen > 0)
    {
        res = FREAcquireByteArray(frePktData, &byteArray);
        if (res != FRE_OK)
        {
            return NULL;
        }
        memcpy(byteArray.bytes, pktData, pktDataLen);
        res = FREReleaseByteArray(frePktData);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    return frePktData;
}

WINPCAP_FRE_FUNC(arrivalPacketGetHandlerRet)
{
    FREResult res;
    ArrivalPacket *arrivalPacket;
    FREObject freHandlerRet = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[0], (uint32_t *)&arrivalPacket);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromInt32(arrivalPacket->handlerRet, &freHandlerRet);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freHandlerRet;
}

WINPCAP_FRE_FUNC(startCaptureThread)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    CaptureThreadParam *captureThreadParam;
    DWORD threadId;
    HANDLE threadHandle = NULL;
    FREObject freThreadParam = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // �X���b�h���J�n����
    captureThreadParam = (CaptureThreadParam *)malloc(sizeof(CaptureThreadParam));
    captureThreadParam->ctx = ctx;
    captureThreadParam->extensionContext = extensionContext;
    captureThreadParam->pcapHandle = pcapHandle;
    captureThreadParam->arrivalPacketList = NULL;
    captureThreadParam->listMutexHandle = CreateMutex(NULL, FALSE, NULL); // create a mutex with no initial owner (unnamed mutex)
    threadHandle = CreateThread(NULL , 0 , pcapCaptureThreadFunc, (LPVOID)captureThreadParam , 0 , &threadId);
    captureThreadParam->threadHandle = threadHandle;

    res = FRENewObjectFromUint32((uint32_t)captureThreadParam, &freThreadParam);
    if (res != FRE_OK)
    {
        return NULL;
    }

    return freThreadParam;
}

WINPCAP_FRE_FUNC(stopCaptureThread)
{
    FREResult res;
    FREObject extensionContext;
    CaptureThreadParam *captureThreadParam;
    pcap_t *pcapHandle;
    HANDLE threadHandle; 
    DWORD waitRet;
    DWORD exitCode;
    int retVal;
    FREObject freRetVal = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&captureThreadParam);
    if (res != FRE_OK)
    {
        return NULL;
    }
    pcapHandle = captureThreadParam->pcapHandle;
    threadHandle = captureThreadParam->threadHandle;

    // ���[�v�������I������
    pcap_breakloop(pcapHandle);
    // �X���b�h�̏I����҂�
    //waitRet = WaitForSingleObject(threadHandle, 1000);
    waitRet = WaitForSingleObject(threadHandle, INFINITE);
    //if (exitCode == STILL_ACTIVE)
    //{
    //    TerminateThread(threadHandle, -1);
    //}
    // �I���R�[�h���擾
    GetExitCodeThread(threadHandle, &exitCode);
    // ���B�p�P�b�g���X�g��j������
    ArrivalPacketList_RemoveAll(&captureThreadParam->arrivalPacketList, captureThreadParam->listMutexHandle);
    // �X���b�h�n���h����j��
    CloseHandle(threadHandle);
    threadHandle =NULL;
    captureThreadParam->threadHandle = NULL;
    // �~���[�e�b�N�X�n���h����j��
    CloseHandle(captureThreadParam->listMutexHandle);
    captureThreadParam->listMutexHandle = NULL;
    // �L���v�`���[�X���b�h�p�����[�^��j������
    free(captureThreadParam);
    captureThreadParam = NULL;

    //retVal = waitRet;
    retVal = exitCode;
    res = FRENewObjectFromInt32(retVal, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

} // extern "C"
