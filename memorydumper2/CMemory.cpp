
#include "CMemory.h"


void DumpCMemory(void (^dump)(const void *ptr, size_t knownSize, long maxDepth, const char *name)) {
    struct S {
        int x;
        int y;
        int z;
    };
    
    struct S s = { 1, 2, 3 };
    dump(&s, sizeof(s), 10, "Simple C struct");
}
