#ifndef __WINPCAPANEDLL_H__
#define __WINPCAPANEDLL_H__

#ifdef WINPCAPANEDLL_EXPORTS
#define WINPCAPANEDLL_API __declspec(dllexport) 
#else
#define WINPCAPANEDLL_API __declspec(dllimport) 
#endif

#include <FlashRuntimeExtensions.h>

#ifdef __cplusplus
extern "C" {
#endif

// ネイティブ拡張の初期化関数
WINPCAPANEDLL_API void ExtInitializer(
    void **extDataToSet,
    FREContextInitializer *ctxInitializerToSet,
    FREContextFinalizer *ctxFinalizerToSet
    );

// ネイティブ拡張の破棄関数
WINPCAPANEDLL_API void ExtFinalizer(void *extData);

#ifdef __cplusplus
} // extern "C"
#endif

#endif