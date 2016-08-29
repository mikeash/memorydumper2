
#include "CMemory.h"

#include <stdlib.h>
#include <string.h>

void DumpCMemory(void (^dump)(const void *ptr, size_t knownSize, long maxDepth, const char *name)) {
    struct S {
        long x;
        long y;
        long z;
    };
    
    S s = { 1, 2, 3 };
    dump(&s, sizeof(s), 10, "Simple C struct");
    
    struct WithPadding {
        char a;
        char b;
        char c;
        short d;
        char e;
        int f;
        char g;
        long h;
    };
    WithPadding withPadding = { 1, 2, 3, 4, 5, 6, 7, 8 };
    dump(&withPadding, sizeof(withPadding), 10, "C struct with padding");
    
    struct MallocLeaf {
        char text[16];
    };
    struct MallocTreeNode1 {
        MallocLeaf *child;
    };
    struct MallocTreeNode2 {
        MallocLeaf *child1;
        MallocLeaf *child2;
    };
    struct MallocTreeRoot {
        MallocTreeNode1 *child1;
        MallocTreeNode2 *child2;
    };
    
    MallocLeaf *leaf1 = (MallocLeaf *)malloc(sizeof(MallocLeaf));
    MallocLeaf *leaf2 = (MallocLeaf *)malloc(sizeof(MallocLeaf));
    MallocTreeNode1 *node1 = (MallocTreeNode1 *)malloc(sizeof(MallocTreeNode1));
    MallocTreeNode2 *node2 = (MallocTreeNode2 *)malloc(sizeof(MallocTreeNode2));
    MallocTreeRoot *root = (MallocTreeRoot *)malloc(sizeof(MallocTreeRoot));
    
    strcpy(leaf1->text, "Leaf here");
    memcpy(leaf2->text, "Something\0Hello!", 16);
    root->child1 = node1;
    root->child2 = node2;
    node1->child = leaf1;
    node2->child1 = leaf1;
    node2->child2 = leaf2;
    dump(&root, sizeof(root), 10, "C tree");
    
    free(root);
    free(node1);
    free(node2);
    free(leaf1);
    free(leaf2);
    
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
