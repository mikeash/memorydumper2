
#ifndef CMemory_h
#define CMemory_h

#include <stddef.h>

#if __cplusplus
extern "C"
#endif
void DumpCMemory(void (^dump)(const void *ptr, size_t knownSize, long maxDepth, const char *name));

#endif /* CMemory_h */
