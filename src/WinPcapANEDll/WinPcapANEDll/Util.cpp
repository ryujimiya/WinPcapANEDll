#include <Windows.h>
#include "util.h"

/// <summary>
/// 文字列をコピーする
/// </summary>
/// <param name="dest">コピー先</param>
/// <param name="destLen">コピー先バッファ長</param>
/// <param name="src">コピー元</param>
void _strCpy(char *dest, int destLen, const char *src)
{
    int strLen = strlen(src);
    strcpy_s(dest, destLen, src);
    dest[strLen] = 0;
}

/// <summary>
/// 文字列をUTF8文字列に変換してコピーする
/// </summary>
/// <param name="dest">コピー先(UTF8)</param>
/// <param name="destLen">コピー先バッファ長</param>
/// <param name="src">コピー元(ShiftJIS)</param>
void _strCpyToUTF8(char *dest, int destLen, const char *src)
{
    ShiftJISToUTF8(src, dest, destLen);
}

/// <summary>
/// 文字列をUTF8文字列に変換してコピーする
/// </summary>
/// <param name="dest">コピー先(ShiftJIS)</param>
/// <param name="destLen">コピー先バッファ長</param>
/// <param name="src">コピー元(UTF8)</param>
void _strCpyToShiftJIS(char *dest, int destLen, const char *src)
{
    UTF8ToShiftJIS(src, dest, destLen);
}

//////////////////////////////////////////////////////////////////////////////////////

//#define MAX_BUFF_SIZE (MAX_PATH)
#define MAX_BUFF_SIZE (4096)

void ShiftJISToUTF8(const char *bufShiftJIS, char *bufUTF8, int bufLenUTF8)
{
    wchar_t bufUnicode[MAX_BUFF_SIZE];

    bufUTF8[0] = 0;
    
    // まずUniocdeに変換する
    // サイズを計算する
    int lenUnicode = MultiByteToWideChar(CP_ACP, 0, bufShiftJIS, strlen(bufShiftJIS)+1, 
                                                  NULL, 0);
    if (lenUnicode <= MAX_BUFF_SIZE)
    {
        MultiByteToWideChar(CP_ACP, 0, bufShiftJIS, strlen(bufShiftJIS)+1, bufUnicode, MAX_BUFF_SIZE);
        // 次に、UniocdeからUTF8に変換する
        // サイズを計算する
        int lenUtf8 = WideCharToMultiByte(CP_UTF8, 0, bufUnicode, lenUnicode, NULL, 0, 
                                                 NULL, NULL);
        if (lenUtf8 <= bufLenUTF8)
        {
            WideCharToMultiByte(CP_UTF8, 0, bufUnicode, lenUnicode, bufUTF8, bufLenUTF8, 
                                     NULL, NULL);
            bufUTF8[lenUtf8] = 0;
        }
    }
}

void UTF8ToShiftJIS(const char *bufUTF8, char *bufShiftJIS, int bufLenShiftJIS)
{
    wchar_t bufUnicode[MAX_BUFF_SIZE];
    
    bufShiftJIS[0] = 0;

    // まずUniocdeに変換する
    // サイズを計算する
    int lenUnicode = MultiByteToWideChar(CP_UTF8, 0, bufUTF8, strlen(bufUTF8) + 1, NULL, 0);
    if (lenUnicode <= MAX_BUFF_SIZE)
    {
        MultiByteToWideChar(CP_UTF8, 0, bufUTF8, strlen(bufUTF8) + 1, bufUnicode, MAX_BUFF_SIZE);
        // 次に、UniocdeからShiftJisに変換する
        // サイズを計算する
        int lenShiftJIS = WideCharToMultiByte(CP_ACP, 0, bufUnicode, lenUnicode, NULL, 0, 
                                                  NULL, NULL);
        if (lenShiftJIS <= bufLenShiftJIS)
        {
            WideCharToMultiByte(CP_ACP, 0, 
                                     bufUnicode, lenUnicode, 
                                     bufShiftJIS, bufLenShiftJIS, 
                                     NULL, NULL);
            bufShiftJIS[lenShiftJIS] = 0;
        }
    }
}

void UnicodeToUTF8(const wchar_t *bufUnicode, char *bufUTF8, int bufLenUTF8)
{
    bufUTF8[0] = 0;

    int lenUnicode = wcslen(bufUnicode);
    // UniocdeからUTF8に変換する
    // サイズを計算する
    int lenUtf8 = WideCharToMultiByte(CP_UTF8, 0, bufUnicode, lenUnicode, NULL, 0, 
                                             NULL, NULL);
    if (lenUtf8 <= bufLenUTF8)
    {
        WideCharToMultiByte(CP_UTF8, 0, bufUnicode, lenUnicode, bufUTF8, bufLenUTF8, 
                                 NULL, NULL);
        bufUTF8[lenUtf8] = 0;
    }
}

void UnicodeToShiftJIS(const wchar_t *bufUnicode, char *bufShiftJIS, int bufLenShiftJIS)
{
    bufShiftJIS[0] = 0;

    int lenUnicode = wcslen(bufUnicode);
    // UniocdeからShiftJisに変換する
    // サイズを計算する
    int lenShiftJIS = WideCharToMultiByte(CP_ACP, 0, bufUnicode, lenUnicode, NULL, 0, 
                                                  NULL, NULL);
    if (lenShiftJIS <= bufLenShiftJIS)
    {
        WideCharToMultiByte(CP_ACP, 0, 
                                 bufUnicode, lenUnicode, 
                                 bufShiftJIS, bufLenShiftJIS, 
                                 NULL, NULL);
        bufShiftJIS[lenShiftJIS] = 0;
    }
}

void UTF8toUnicode(const char *bufUTF8, wchar_t *bufUnicode, int bufLenUnicode)
{
    // UTF8からUniocdeに変換する
    // サイズを計算する
    int lenUnicode = MultiByteToWideChar(CP_UTF8, 0, bufUTF8, strlen(bufUTF8) + 1, NULL, 0);
    if (lenUnicode <= bufLenUnicode)
    {
        MultiByteToWideChar(CP_UTF8, 0, bufUTF8, strlen(bufUTF8) + 1, bufUnicode, bufLenUnicode);
    }
}

void ShiftJIStoUnicode(const char *bufShiftJIS, wchar_t *bufUnicode, int bufLenUnicode)
{
    // ShiftJISからUniocdeに変換する
    // サイズを計算する
    int lenUnicode = MultiByteToWideChar(CP_ACP, 0, bufShiftJIS, strlen(bufShiftJIS)+1, 
                                                  NULL, 0);
    if (lenUnicode <= bufLenUnicode)
    {
        MultiByteToWideChar(CP_ACP, 0, bufShiftJIS, strlen(bufShiftJIS)+1, bufUnicode, bufLenUnicode);
    }
}
