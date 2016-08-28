
#include "CMemory.h"


void DumpCMemory(void (^dump)(const void *ptr, size_t knownSize, long maxDepth, const char *name)) {
    struct S {
        long x;
        long y;
        long z;
    };
    
    S s = { 1, 2, 3 };
    dump(&s, sizeof(s), 10, "Simple C struct");
    
    class SimpleClass {
    public:
        long x;
        
        virtual void f() {}
        virtual void g() {}
        virtual void h() {}
    };
    
    SimpleClass simpleClass;
    simpleClass.x = 1;
    dump(&simpleClass, sizeof(simpleClass), 10, "Simple C++ class");
    
    class SimpleSubclass: public SimpleClass {
    public:
        long y;
        
        virtual void i() {}
        virtual void j() {}
    };
    
    SimpleSubclass simpleSubclass;
    simpleSubclass.x = 1;
    simpleSubclass.y = 2;
    dump(&simpleSubclass, sizeof(simpleSubclass), 10, "Simple C++ subclass");
    
    class SecondSuperclass {
    public:
        long z;
        
        virtual void k() {}
        virtual void l() {}
    };
    
    class MultipleInheritanceSubclass: public SimpleClass, SecondSuperclass {
    public:
        long a;
    };
    
    MultipleInheritanceSubclass multipleInheritanceSubclass;
    multipleInheritanceSubclass.x = 1;
    multipleInheritanceSubclass.a = 2;
    dump(&multipleInheritanceSubclass, sizeof(multipleInheritanceSubclass), 10, "C++ subclass with two superclasses");
}
