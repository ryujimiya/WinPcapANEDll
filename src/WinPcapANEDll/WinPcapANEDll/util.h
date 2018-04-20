#ifndef __UTIL_H__
#define __UTIL_H__

void _strCpy(char *dest, int destLen, const char *src);
void _strCpyToUTF8(char *dest, int destLen, const char *src);
void _strCpyToShiftJIS(char *dest, int destLen, const char *src);

void ShiftJISToUTF8(const char *bufShiftJIS, char *bufUTF8, int bufLenUTF8);
void UTF8ToShiftJIS(const char *bufUTF8, char *bufShiftJIS, int bufLenShiftJIS);
void UnicodeToUTF8(const wchar_t *bufUnicode, char *bufUTF8, int bufLenUTF8);
void UnicodeToShiftJIS(const wchar_t *bufUnicode, char *bufShiftJIS, int bufLenShiftJIS);
void UTF8toUnicode(const char *bufUTF8, wchar_t *bufUnicode, int bufLenUnicode);
void ShiftJIStoUnicode(const char *bufShiftJIS, wchar_t *bufUnicode, int bufLenUnicode);

#endif