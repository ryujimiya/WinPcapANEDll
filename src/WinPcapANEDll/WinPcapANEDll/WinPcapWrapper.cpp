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
// util
///////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// int配列FREObjectを取得する
/// </summary>
/// <param name="len">配列サイズ</param>
/// <param name="ary">配列</param>
/// <returns></returns>
static FREObject _FRENewObjectFromIntArray(int len, int *ary)
{
    int i;
    FREResult res;
    FREObject freVal;
    FREObject freAry = NULL;

    res = FRENewObject((const uint8_t *)"Array", 0, NULL, &freAry, NULL);
    if (res != FRE_OK)
    {
        return  NULL;
    }
    res = FRESetArrayLength(freAry, len);
    if (res != FRE_OK)
    {
        return NULL;
    }
    for (i = 0; i < len; i++)
    {
        res = FRENewObjectFromInt32(ary[i], &freVal);
        if (res != FRE_OK)
        {
            return NULL;
        }
        res = FRESetArrayElementAt(freAry, i, freVal);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    return freAry;
}

/// <summary>
/// pcap_rmtauth構造体を取得する
/// </summary>
/// <param name="freAuth"></param>
/// <param name="authp">セットするpcap_rmtauthへのポインタ</param>
/// <returns>成功すれば引数と同じpcap_rmtauthへのポインタ、失敗したときはNULL</returns>
static struct pcap_rmtauth *getPcapRmtAuthFromFREObject(FREObject freAuth, struct pcap_rmtauth *authp)
{
    int userNameLen = 0;
    char *userName = NULL;
    int passwordLen = 0;
    char *password = NULL;
    FREResult res;
    FREObject freAuthType = NULL;
    FREObject freAuthUserName = NULL;
    FREObject freAuthPassword = NULL;

    if (freAuth == NULL)
    {
        return NULL;
    }
    if (authp == NULL)
    {
        return NULL;
    }
    res = FREGetObjectProperty(freAuth, (const uint8_t *)"type", &freAuthType, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(freAuthType, &authp->type);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectProperty(freAuth, (const uint8_t *)"userName", &freAuthUserName, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (freAuthUserName != NULL)
    {
        res = FREGetObjectAsUTF8(freAuthUserName, (uint32_t *)&userNameLen, (const uint8_t **)&userName);
        if (res != FRE_OK)
        {
            return NULL;
        }
        authp->username = userName;
    }
    else
    {
        authp->username = NULL;
    }
    res = FREGetObjectProperty(freAuth, (const uint8_t *)"password", &freAuthPassword, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (freAuthPassword != NULL)
    {
        res = FREGetObjectAsUTF8(freAuthPassword, (uint32_t *)&passwordLen, (const uint8_t **)&password);
        if (res != FRE_OK)
        {
            return NULL;
        }
        authp->password = password;
    }
    else
    {
        authp->password = NULL;
    }
    return authp;
}

///////////////////////////////////////////////////////////////////////////////////
// WinPcap exported functions
///////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// libpcapライブラリのバージョン情報を取得する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapLibVersion)
{
    const char *versionStr = NULL;
    char versionStrUTF8[MAX_BUF_SIZE];
    FREResult res;
    FREObject freVersion = NULL;

    // API
    versionStr = pcap_lib_version();

    _strCpyToUTF8(versionStrUTF8, sizeof(versionStrUTF8), versionStr);
    res = FRENewObjectFromUTF8(strlen(versionStrUTF8), (const uint8_t *)versionStrUTF8, &freVersion); 
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freVersion;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapMajorVersion)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int majorVer = 0;
    FREObject freMajorVer = NULL;

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

    // API
    majorVer = pcap_major_version(pcapHandle);

    res = FRENewObjectFromInt32(majorVer, &freMajorVer);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freMajorVer;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapMinorVersion)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int minorVer = 0;
    FREObject freMinorVer = NULL;

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

    // API
    minorVer = pcap_minor_version(pcapHandle);

    res = FRENewObjectFromInt32(minorVer, &freMinorVer);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freMinorVer;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapGetErr)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    const char *errStr;
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    FREObject freErrBuf = NULL;

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

    // API
    errStr = pcap_geterr(pcapHandle);

    if (errStr != NULL)
    {
        _strCpyToUTF8(errBufUTF8, sizeof(errBufUTF8), errStr);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }
    return freErrBuf;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapStrError)
{
    FREResult res;
    FREObject extensionContext;
    int error;
    const char *errStr;
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    FREObject freErrBuf = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&error);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    errStr = pcap_strerror(error);

    if (errStr != NULL)
    {
        _strCpyToUTF8(errBufUTF8, sizeof(errBufUTF8), errStr);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }
    return freErrBuf;
}

/// <summary>
/// すべてのデバイスを列挙する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapFindAllDevs)
{
    pcap_if_t *alldevsp = NULL;
    char errBuf[PCAP_ERRBUF_SIZE];
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    int ret;
    FREResult res;
    FREObject extensionContext;
    FREObject freRetVal = NULL;
    FREObject freAlldevsp = NULL;
    FREObject freErrBuf = NULL;
    FREObject resAllDevsArg[4];
    FREObject resAllDevs = NULL;
    FREObject methodResult = NULL;

    if (argc != 1)
    {
        return NULL;
    }
    extensionContext = arg[0];

    // API
    ret = pcap_findalldevs(&alldevsp, errBuf);

    // 結果をFREObjectに変換する
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)alldevsp, &freAlldevsp);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (ret != 0)
    {
        // APIがエラーのときはエラー文字列を格納する
        _strCpyToUTF8(errBufUTF8, sizeof(errBufUTF8), errBuf);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }

    resAllDevsArg[0] = extensionContext;
    resAllDevsArg[1] = freRetVal;
    resAllDevsArg[2] = freAlldevsp;
    resAllDevsArg[3] = freErrBuf;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultAllDevs", sizeof(resAllDevsArg)/ sizeof(FREObject), resAllDevsArg, &resAllDevs, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }

    return resAllDevs;
}

/// <summary>
/// すべてのデバイスを列挙する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapFindAllDevsEx)
{
    int sourceLen = 0;
    char *source = NULL;
    struct pcap_rmtauth *authp = NULL;
    struct pcap_rmtauth auth;
    pcap_if_t *alldevsp = NULL;
    char errBuf[PCAP_ERRBUF_SIZE];
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    int ret;
    FREResult res;
    FREObject extensionContext;
    FREObject freRetVal = NULL;
    FREObject freAlldevsp = NULL;
    FREObject freErrBuf = NULL;
    FREObject resAllDevsArg[4];
    FREObject resAllDevs = NULL;
    FREObject methodResult = NULL;

    if (argc != 3)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUTF8(arg[1], (uint32_t *)&sourceLen, (const uint8_t **)&source);
    if (res != FRE_OK)
    {
        return NULL;
    }
    authp = getPcapRmtAuthFromFREObject(arg[2], &auth);
    
    // API
    ret = pcap_findalldevs_ex(source, authp, &alldevsp, errBuf);

    // 結果をFREObjectに変換する
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)alldevsp, &freAlldevsp);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (ret != 0)
    {
        // APIがエラーのときはエラー文字列を格納する
        _strCpyToUTF8(errBufUTF8, sizeof(errBufUTF8), errBuf);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }

    resAllDevsArg[0] = extensionContext;
    resAllDevsArg[1] = freRetVal;
    resAllDevsArg[2] = freAlldevsp;
    resAllDevsArg[3] = freErrBuf;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultAllDevs", sizeof(resAllDevsArg)/ sizeof(FREObject), resAllDevsArg, &resAllDevs, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }

    return resAllDevs;
}

/// <summary>
/// 列挙したすべてのデバイスを解放する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapFreeAllDevs)
{
    FREResult res;
    FREObject extensionContext;
    pcap_if_t *alldevsp = NULL;
    int ret = -1;
    FREObject freRetVal = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&alldevsp);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    pcap_freealldevs(alldevsp);

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// ソース文字列を作成する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapCreateSrcStr)
{
    FREObject extensionContext;
    int type;
    int hostLen;
    char *host;
    int portLen;
    char *port;
    int nameLen;
    char *name;
    char nameShiftJIS[MAX_BUF_SIZE];
    char *nameShiftJISp = NULL;
    char source[PCAP_BUF_SIZE];
    char sourceUTF8[PCAP_BUF_SIZE];
    char errBuf[PCAP_ERRBUF_SIZE];
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    int ret;
    FREResult res;
    FREObject freRetVal = NULL;
    FREObject freSource = NULL;
    FREObject freErrBuf = NULL;
    FREObject resSrcStrArg[8];
    FREObject resSrcStr = NULL;

    if (argc != 5)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsInt32(arg[1], (int32_t *)&type);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (arg[2] != NULL)
    {
        res = FREGetObjectAsUTF8(arg[2], (uint32_t *)&hostLen, (const uint8_t **)&host);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        hostLen = 0;
        host = NULL;
    }
    if (arg[3] != NULL)
    {
        res = FREGetObjectAsUTF8(arg[3], (uint32_t *)&portLen, (const uint8_t **)&port);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        portLen = 0;
        port = NULL;
    }
    if (arg[4] != NULL)
    {
        res = FREGetObjectAsUTF8(arg[4], (uint32_t *)&nameLen, (const uint8_t **)&name);
        if (res != FRE_OK)
        {
            return NULL;
        }
        _strCpyToShiftJIS(nameShiftJIS, sizeof(nameShiftJIS), name);
        nameShiftJISp = nameShiftJIS;
    }
    else
    {
        nameLen = 0;
        name = NULL;
        nameShiftJISp = NULL;
    }

    memset(source, 0, sizeof(source));
    // API
    ret = pcap_createsrcstr(source, type, host, port, nameShiftJISp, errBuf);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    _strCpyToUTF8(sourceUTF8, sizeof(sourceUTF8), source);
    res = FRENewObjectFromUTF8(strlen(sourceUTF8), (const uint8_t *)sourceUTF8, &freSource);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (ret != 0)
    {
        // APIがエラーのときはエラー文字列を格納する
        _strCpyToUTF8(errBufUTF8, sizeof(errBufUTF8), errBuf);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }

    resSrcStrArg[0] = extensionContext;
    resSrcStrArg[1] = freRetVal;
    resSrcStrArg[2] = freSource;
    resSrcStrArg[3] = NULL;
    resSrcStrArg[4] = NULL;
    resSrcStrArg[5] = NULL;
    resSrcStrArg[6] = NULL;
    resSrcStrArg[7] = freErrBuf;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultPcapSrcStr", sizeof(resSrcStrArg)/sizeof(FREObject), resSrcStrArg, &resSrcStr, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return resSrcStr;
}

/// <summary>
/// ソース文字列をパースする
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapParseSrcStr)
{
    FREObject extensionContext;
    int sourceLen;
    char *source;
    char souruceShiftJIS[PCAP_BUF_SIZE];
    int type;
    char host[PCAP_BUF_SIZE];
    char port[PCAP_BUF_SIZE];
    char name[PCAP_BUF_SIZE];
    char nameUTF8[PCAP_BUF_SIZE];
    char errBuf[PCAP_ERRBUF_SIZE];
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    int ret;
    FREResult res;
    FREObject freRetVal = NULL;
    FREObject freType = NULL;
    FREObject freHost = NULL;
    FREObject frePort = NULL;
    FREObject freName = NULL;
    FREObject freErrBuf = NULL;
    FREObject resSrcStrArg[8];
    FREObject resSrcStr = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUTF8(arg[1], (uint32_t *)&sourceLen, (const uint8_t **)&source);
    if (res != FRE_OK)
    {
        return NULL;
    }
    _strCpyToShiftJIS(souruceShiftJIS, sizeof(souruceShiftJIS), source);

    // API
    ret = pcap_parsesrcstr(souruceShiftJIS, &type, host, port, name, errBuf);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(type, &freType);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (host != NULL)
    {
        res = FRENewObjectFromUTF8(strlen(host), (const uint8_t *)host, &freHost);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freHost = NULL;
    }
    if (port != NULL)
    {
        res = FRENewObjectFromUTF8(strlen(port), (const uint8_t *)port, &frePort);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        frePort = NULL;
    }
    if (name!= NULL)
    {
        _strCpy(nameUTF8, sizeof(nameUTF8), name);
        res = FRENewObjectFromUTF8(strlen(nameUTF8), (const uint8_t *)nameUTF8, &freName);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freName = NULL;
    }
    if (ret != 0)
    {
        // APIがエラーのときはエラー文字列を格納する
        _strCpy(errBufUTF8, sizeof(errBufUTF8), errBuf);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }
    resSrcStrArg[0] = extensionContext;
    resSrcStrArg[1] = freRetVal;
    resSrcStrArg[2] = NULL;
    resSrcStrArg[3] = freType;
    resSrcStrArg[4] = freHost;
    resSrcStrArg[5] = frePort;
    resSrcStrArg[6] = freName;
    resSrcStrArg[7] = freErrBuf;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultPcapSrcStr", sizeof(resSrcStrArg)/sizeof(FREObject), resSrcStrArg, &resSrcStr, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return resSrcStr;
}

/// <summary>
/// デバイスをオープンする
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapOpen)
{
    int sourceLen = 0;
    char *source = NULL;
    int snapLen = 0;
    int flags = 0;
    int readTimeout =0;
    struct pcap_rmtauth *authp = NULL;
    struct pcap_rmtauth auth;
    int ret = 0;
    pcap_t *pcapHandle = NULL;
    char errBuf[PCAP_ERRBUF_SIZE];
    char errBufUTF8[PCAP_ERRBUF_SIZE];
    FREResult res;
    FREObject extensionContext;
    FREObject freRetVal = NULL;
    FREObject frePcapHandle = NULL;
    FREObject freErrBuf = NULL;
    FREObject resPcapArg[4];
    FREObject resPcap = NULL;

    if (argc != 6)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUTF8(arg[1], (uint32_t *)&sourceLen, (const uint8_t **)&source);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[2], (int32_t *)&snapLen);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[3], (int32_t *)&flags);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[4], (int32_t *)&readTimeout);
    if (res != FRE_OK)
    {
        return NULL;
    }
    authp = getPcapRmtAuthFromFREObject(arg[5], &auth);
    
    // API
    pcapHandle = pcap_open(source, snapLen, flags, readTimeout, authp, errBuf);
    
    // 結果を格納
    //  Note:この関数はretに相当するものはない。常に0を返す
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)pcapHandle, &frePcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (pcapHandle == NULL)
    {
        // APIがエラーのときはエラー文字列を格納する
        _strCpyToUTF8(errBufUTF8, sizeof(errBufUTF8), errBuf);
        res = FRENewObjectFromUTF8(strlen(errBufUTF8), (const uint8_t *)errBufUTF8, &freErrBuf);
        if (res != FRE_OK)
        {
             return NULL;
        }
    }
    else
    {
        freErrBuf = NULL;
    }

    resPcapArg[0] = extensionContext;
    resPcapArg[1] = freRetVal;
    resPcapArg[2] = frePcapHandle;
    resPcapArg[3] = freErrBuf;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultPcap", sizeof(resPcapArg)/ sizeof(FREObject), resPcapArg, &resPcap, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }

    return resPcap;
}

/// <summary>
/// デバイスをクローズする
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapClose)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle = NULL;
    int ret = -1;
    FREObject freRetVal = NULL;

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

    // API
    pcap_close(pcapHandle);

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 次のパケットを取得する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapNextEx)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle = NULL;
    struct pcap_pkthdr *header = NULL;
    u_char *data = NULL;
    int capLen = 0;
    int ret = 0;
    FREObject freRetVal = NULL;
    FREObject freHeader = NULL;
    FREObject freData = NULL;
    FREObject length = NULL;
    FREByteArray byteArray;
    FREObject resPcapNextArg[4];
    FREObject resPcapNext = NULL;

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

    // API
    ret = pcap_next_ex(pcapHandle, &header, (const u_char **)&data);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (header != NULL)
    {
        res = FRENewObjectFromUint32((uint32_t)header, &freHeader);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freHeader = NULL;
    }
    if (ret == 1)
    {
        capLen = header->caplen;
    }
    else
    {
        capLen = 0;
    }
    res = FRENewObject((const uint8_t *)"flash.utils.ByteArray", 0, NULL, &freData, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromInt32(capLen, &length);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRESetObjectProperty(freData, (const uint8_t*)"length", length, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    if (capLen > 0)
    {
        res = FREAcquireByteArray(freData, &byteArray);
        if (res != FRE_OK)
        {
            return NULL;
        }
        memcpy(byteArray.bytes, data, capLen);
        res = FREReleaseByteArray(freData);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }

    resPcapNextArg[0] = extensionContext;
    resPcapNextArg[1] = freRetVal;
    resPcapNextArg[2] = freHeader;
    resPcapNextArg[3] = freData;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultPcapNext", sizeof(resPcapNextArg)/ sizeof(FREObject), resPcapNextArg, &resPcapNext, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return resPcapNext;
}

/// <summary>
/// パケットを書き込むファイルをオープンする
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDumpOpen)
{
    pcap_t *pcapHandle = NULL;
    int fnameLen = 0;
    char *fname = NULL;
    char fnameShiftJIS[MAX_BUF_SIZE];
    pcap_dumper_t *pcapDumpHandle = NULL;
    FREResult res;
    FREObject extensionContext;
    FREObject frePcapDumpHandle = NULL;
    FREObject resPcapDumpArg[2];
    FREObject resPcapDump = NULL;

    if (argc != 3)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUTF8(arg[2], (uint32_t *)&fnameLen, (const uint8_t **)&fname);
    if (res != FRE_OK)
    {
        return NULL;
    }
    _strCpyToShiftJIS(fnameShiftJIS, sizeof(fnameShiftJIS), fname);

    // API
    pcapDumpHandle = pcap_dump_open(pcapHandle, fnameShiftJIS);
    
    // 結果を格納
    res = FRENewObjectFromUint32((uint32_t)pcapDumpHandle, &frePcapDumpHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }

    resPcapDumpArg[0] = extensionContext;
    resPcapDumpArg[1] = frePcapDumpHandle;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultPcapDump", sizeof(resPcapDumpArg)/ sizeof(FREObject), resPcapDumpArg, &resPcapDump, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }

    return resPcapDump;
}

/// <summary>
/// パケットを書き込むファイルをクローズする
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDumpClose)
{
    FREResult res;
    FREObject extensionContext;
    pcap_dumper_t *pcapDumpHandle = NULL;
    int ret = -1;
    FREObject freRetVal = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapDumpHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    pcap_dump_close(pcapDumpHandle);

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// パケットを書き込む
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDump)
{
    FREResult res;
    FREObject extensionContext;
    pcap_dumper_t *pcapDumpHandle;
    struct pcap_pkthdr *header;
    FREObject freData;
    FREByteArray byteArray;
    u_char *data = NULL;
    int ret = -1;
    FREObject freRetVal = NULL;

    if (argc != 4)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapDumpHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[2], (uint32_t *)&header);
    if (res != FRE_OK)
    {
        return NULL;
    }
    freData = arg[3];
    res = FREAcquireByteArray(freData, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }
    data = byteArray.bytes;

    // API
    pcap_dump((u_char *)pcapDumpHandle, header, data);

    res = FREReleaseByteArray(freData);
    if (res != FRE_OK)
    {
        return NULL;
    }

    ret = 0;
    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// パケット書き込みバッファをフラッシュする
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDumpFlush)
{
    FREResult res;
    FREObject extensionContext;
    pcap_dumper_t *pcapDumpHandle = NULL;
    int ret = 0;
    FREObject freRetVal = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapDumpHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    ret = pcap_dump_flush(pcapDumpHandle);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// パケット書き込み位置を取得する
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDumpFTell)
{
    FREResult res;
    FREObject extensionContext;
    pcap_dumper_t *pcapDumpHandle = NULL;
    long pos = 0;
    FREObject frePos = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapDumpHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    pos = pcap_dump_ftell(pcapDumpHandle);

    res = FRENewObjectFromInt32(pos, &frePos);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return frePos;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDataLink)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int dlt = 0;
    FREObject freDlt = NULL;

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

    // API
    dlt = pcap_datalink(pcapHandle);

    res = FRENewObjectFromInt32(dlt, &freDlt);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freDlt;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapListDataLinks)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int dltCnt = 0;
    int *dltAry = NULL;
    FREObject freDltAry = NULL;

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

    // API
    dltCnt = pcap_list_datalinks(pcapHandle, &dltAry);

    if (dltCnt >= 0)
    {
        freDltAry = _FRENewObjectFromIntArray(dltCnt, dltAry);
        if (dltAry != NULL)
        {
            pcap_free_datalinks(dltAry);
        }
    }
    else
    {
        freDltAry = NULL;
    }

    return freDltAry;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSetDataLink)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int dlt;
    int ret;
    FREObject freRetVal = NULL;

    if (argc != 3)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[2], (int32_t *)&dlt);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    ret = pcap_set_datalink(pcapHandle, dlt);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDataLinkNameToVal)
{
    FREResult res;
    FREObject extensionContext;
    int dltNameLen = 0;
    char *dltName;
    int dlt;
    FREObject freDlt = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUTF8(arg[1], (uint32_t *)&dltNameLen, (const uint8_t **)&dltName);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    dlt = pcap_datalink_name_to_val(dltName);
    
    res = FRENewObjectFromInt32(dlt, &freDlt);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freDlt;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDataLinkValToDescription)
{
    FREResult res;
    FREObject extensionContext;
    int dlt;
    const char *dltDescr;
    char dltDescrUTF8[MAX_BUF_SIZE];
    FREObject freDltDescr = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsInt32(arg[1], (int32_t *)&dlt);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    dltDescr = pcap_datalink_val_to_description(dlt);
    
    if (dltDescr != NULL)
    {
        _strCpyToUTF8(dltDescrUTF8, sizeof(dltDescrUTF8), dltDescr);
        res = FRENewObjectFromUTF8(strlen(dltDescrUTF8), (const uint8_t *)dltDescrUTF8, &freDltDescr);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freDltDescr = NULL;
    }
    return freDltDescr;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapDataLinkValToName)
{
    FREResult res;
    FREObject extensionContext;
    int dlt;
    const char *dltName;
    char dltNameUTF8[MAX_BUF_SIZE];
    FREObject freDltName = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsInt32(arg[1], (int32_t *)&dlt);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    dltName = pcap_datalink_val_to_name(dlt);
    
    if (dltName != NULL)
    {
        _strCpyToUTF8(dltNameUTF8, sizeof(dltNameUTF8), dltName);
        res = FRENewObjectFromUTF8(strlen(dltNameUTF8), (const uint8_t *)dltNameUTF8, &freDltName);
        if (res != FRE_OK)
        {
            return NULL;
        }
    }
    else
    {
        freDltName = NULL;
    }
    return freDltName;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSetMode)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int mode;
    int ret = 0;
    FREObject freRetVal = NULL;

    if (argc != 3)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[2], (int32_t *)&mode);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    ret = pcap_setmode(pcapHandle, mode);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSetFilter)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    int filterStrLen = 0;
    char *filterStr;
    int optimize;
    bpf_u_int32 netmask;
    struct bpf_program fp;
    int ret;
    FREObject freRetVal;

    if (argc != 5)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUTF8(arg[2], (uint32_t *)&filterStrLen, (const uint8_t **)&filterStr);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[3], (int32_t *)&optimize);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[4], (uint32_t *)&netmask);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    ret = pcap_compile(pcapHandle, &fp,filterStr, optimize, netmask);
    if (ret == -1)
    {
        return NULL;
    }
    // API
    ret = pcap_setfilter(pcapHandle, &fp);
    // API
    pcap_freecode(&fp);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapStats)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    struct pcap_stat pcapStat;
    int ret = 0;
    FREObject freRetVal = NULL;
    FREObject frePcapStat = NULL;
    FREObject resPcapStatsArg[3];
    FREObject resPcapStats = NULL;

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

    memset(&pcapStat, 0, sizeof(struct pcap_stat));
    // API
    ret = pcap_stats(pcapHandle, &pcapStat);

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FRENewObjectFromUint32((uint32_t)&pcapStat, &frePcapStat);
    if (res != FRE_OK)
    {
        return NULL;
    }
    resPcapStatsArg[0] = extensionContext;
    resPcapStatsArg[1] = freRetVal;
    resPcapStatsArg[2] = frePcapStat;
    res = FRENewObject((const uint8_t *)"livefan.winpcap.ResultPcapStats", sizeof(resPcapStatsArg) / sizeof(FREObject), resPcapStatsArg, &resPcapStats, NULL);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return resPcapStats;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSendPacket)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    FREObject freData;
    FREByteArray byteArray;
    int ret = 0;
    FREObject freRetVal = NULL;

    if (argc != 3)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    freData = arg[2];
    res = FREAcquireByteArray(freData, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API
    ret = pcap_sendpacket(pcapHandle, byteArray.bytes, byteArray.length);

    res = FREReleaseByteArray(freData);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSendQueueAlloc)
{
    FREResult res;
    FREObject extensionContext;
    u_int memSize;
    struct pcap_send_queue *queue = NULL;
    FREObject freQueue = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], &memSize);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API (sendqueue関連はWPCAP定義が必要)
    queue = pcap_sendqueue_alloc(memSize);

    res = FRENewObjectFromUint32((uint32_t)queue, &freQueue);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freQueue;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSendQueueDestroy)
{
    FREResult res;
    FREObject extensionContext;
    struct pcap_send_queue *queue;
    int retVal = 0;
    FREObject freRetVal = NULL;

    if (argc != 2)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&queue);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API (sendqueue関連はWPCAP定義が必要)
    pcap_sendqueue_destroy(queue);

    retVal = 0; // 常に成功
    res = FRENewObjectFromInt32(retVal, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSendQueueQueue)
{
    FREResult res;
    FREObject extensionContext;
    struct pcap_send_queue *queue;
    struct pcap_pkthdr *header;
    FREObject freData;
    FREByteArray byteArray;
    int dataLen = 0;
    u_char *data = NULL;
    int ret = 0;
    FREObject freRetVal = NULL;

    if (argc != 4)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&queue);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[2], (uint32_t *)&header);
    if (res != FRE_OK)
    {
        return NULL;
    }
    freData = arg[3];
    res = FREAcquireByteArray(freData, &byteArray);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API (sendqueue関連はWPCAP定義が必要)
    dataLen = byteArray.length;
    data = byteArray.bytes;
    ret = pcap_sendqueue_queue(queue, header, data);

    res = FREReleaseByteArray(freData);
    if (res != FRE_OK)
    {
        return NULL;
    }

    res = FRENewObjectFromInt32(ret, &freRetVal);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freRetVal;
}

/// <summary>
/// 
/// </summary>
/// <param name="ctx"></param>
/// <param name="funcData"></param>
/// <param name="argc"></param>
/// <param name="arg"></param>
/// <returns></returns>
WINPCAP_FRE_FUNC(pcapSendQueueTransmit)
{
    FREResult res;
    FREObject extensionContext;
    pcap_t *pcapHandle;
    struct pcap_send_queue *queue;
    int sync;
    u_int sendLen = 0;
    FREObject freSendLen = NULL;

    if (argc != 4)
    {
        return NULL;
    }
    extensionContext = arg[0];
    res = FREGetObjectAsUint32(arg[1], (uint32_t *)&pcapHandle);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsUint32(arg[2], (uint32_t *)&queue);
    if (res != FRE_OK)
    {
        return NULL;
    }
    res = FREGetObjectAsInt32(arg[3], &sync);
    if (res != FRE_OK)
    {
        return NULL;
    }

    // API (sendqueue関連はWPCAP定義が必要)
    sendLen = pcap_sendqueue_transmit(pcapHandle, queue, sync);

    res = FRENewObjectFromUint32(sendLen, &freSendLen);
    if (res != FRE_OK)
    {
        return NULL;
    }
    return freSendLen;
}



} // extern "C"
