#pragma once

#ifdef _WIN32
  #ifdef DLL_EXPORTS
    #define API __declspec(dllexport)
  #else
    #define API __declspec(dllimport)
  #endif
#else
  #define API
#endif

#ifdef __cplusplus
extern "C" {
#endif

API double convert_shoe_size(double size, const char* from_system, const char* to_system);

#ifdef __cplusplus
}
#endif
