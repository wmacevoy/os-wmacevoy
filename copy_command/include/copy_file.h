#pragma once

#ifdef _WIN32
#ifdef BUILDING_COPY_FILE
#define COPY_FILE_API __declspec(dllexport)
#else
#define COPY_FILE_API __declspec(dllimport)
#endif
#else
#define COPY_FILE_API
#endif

#if defined(__cplusplus)
extern "C" {
#endif
  
COPY_FILE_API int copy_file(const char *source, const char *destination);

#if defined(__cplusplus)
} / * extern "C" */
#endif
