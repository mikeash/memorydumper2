
import AppKit


typealias Pointer = UnsafePointer<Void>


func symbolInfo(_ ptr: Pointer) -> Dl_info? {
    var info = Dl_info()
    let result = dladdr(ptr, &info)
    return result == 0 ? nil : info
}

func symbolName(_ ptr: Pointer) -> String? {
    if let info = symbolInfo(ptr) {
        if let symbolAddr = info.dli_saddr where Pointer(symbolAddr) == ptr {
            return String(cString: info.dli_sname)
        }
    }
    return nil
}

func nextSymbol(ptr: Pointer, limit: Int) -> Pointer? {
    if let info = symbolInfo(ptr) {
        for i in 1..<limit {
            let candidate = ptr + i
            guard let candidateInfo = symbolInfo(candidate) else { return nil }
            if info.dli_saddr != candidateInfo.dli_saddr {
                return candidate
            }
        }
    }
    return nil
}

func symbolLength(ptr: Pointer, limit: Int) -> Int? {
    return nextSymbol(ptr: ptr, limit: limit).map({ $0 - ptr })
}

extension mach_vm_address_t {
    init(_ ptr: Pointer?) {
        self.init(UInt(bitPattern: ptr))
    }
}

func safeRead(ptr: Pointer, into: inout [UInt8]) -> Bool {
    let result = into.withUnsafeMutableBufferPointer({ bufferPointer -> kern_return_t in
        var outSize: mach_vm_size_t = 0
        return mach_vm_read_overwrite(
            mach_task_self_,
            mach_vm_address_t(ptr),
            mach_vm_size_t(bufferPointer.count),
            mach_vm_address_t(bufferPointer.baseAddress),
            &outSize)
    })
    return result == KERN_SUCCESS
}

func safeRead(ptr: Pointer, limit: Int) -> [UInt8] {
    var buffer: [UInt8] = []
    var eightBytes: [UInt8] = Array(repeating: 0, count: 8)
    while buffer.count < limit {
        let success = safeRead(ptr: ptr + buffer.count, into: &eightBytes)
        if !success {
            break
        }
        buffer.append(contentsOf: eightBytes)
    }
    return buffer
}

func hexString<Seq: Sequence where Seq.Iterator.Element == UInt8>(bytes: Seq, limit: Int? = nil, separator: String = " ") -> String {
    let spacesInterval = 8
    var result = ""
    for (index, byte) in bytes.enumerated() {
        if let limit = limit where index >= limit {
            result.append("...")
            break
        }
        if index > 0 && index % spacesInterval == 0 {
            result.append(separator)
        }
        result.append(String(format: "%02x", byte))
    }
    return result
}

struct PointerAndOffset {
    var pointer: Pointer?
    var offset: Int
}

struct Memory {
    var buffer: [UInt8]
    var isMalloc: Bool
    var symbolName: String?
    
    init(buffer: [UInt8]) {
        self.buffer = buffer
        self.isMalloc = false
    }
    
    init?(ptr: Pointer?, knownSize: Int? = nil) {
        guard let ptr = ptr else { return nil }
        let mallocLength = malloc_size(ptr)
        
        isMalloc = mallocLength > 0
        symbolName = symbolInfo(ptr).flatMap({ String(cString: $0.dli_sname) })
        
        let length = knownSize ?? symbolLength(ptr: ptr, limit: 4096) ?? mallocLength
        if length > 0 {
            buffer = Array(repeating: 0, count: length)
            let success = safeRead(ptr: ptr, into: &buffer)
            if !success {
                return nil
            }
        } else {
            buffer = safeRead(ptr: ptr, limit: 128)
            if buffer.isEmpty {
                return nil
            }
        }
    }
    
    func scanPointers() -> [PointerAndOffset] {
        return buffer.withUnsafeBufferPointer({ bufferPointer in
            let castBufferPointer = UnsafeBufferPointer(start: UnsafePointer<Pointer?>(bufferPointer.baseAddress), count: bufferPointer.count / sizeof(Pointer.self))
            return castBufferPointer.enumerated().map({ PointerAndOffset(pointer: $1, offset: $0 * sizeof(Pointer.self)) })
            let pointerPointer = UnsafePointer<Pointer>(bufferPointer.baseAddress)
            let pointerCount = bufferPointer.count / sizeof(Pointer.self)
            var result: [PointerAndOffset] = []
            for i in 0..<pointerCount {
                let val = PointerAndOffset(pointer: UnsafePointer(bitPattern: 0xdeadbeef)!, offset: i * sizeof(Pointer.self))
                result.append(val)
            }
            return result
        })
    }
}

class MemoryRegion {
    var depth: Int
    let pointer: Pointer
    let memory: Memory
    var children: [Child] = []
    var didScan = false
    
    init(depth: Int, pointer: Pointer, memory: Memory) {
        self.depth = depth
        self.pointer = pointer
        self.memory = memory
    }
    
    struct Child {
        var offset: Int
        var region: MemoryRegion
    }
}

extension MemoryRegion: Hashable {
    var hashValue: Int {
        return pointer.hashValue
    }
}

func ==(lhs: MemoryRegion, rhs: MemoryRegion) -> Bool {
    return lhs.pointer == rhs.pointer
}

func buildMemoryRegionTree<T>(value: T, maxDepth: Int) -> [MemoryRegion] {
    var value = value
    let maybeRootRegion = withUnsafePointer(&value, { ptr -> MemoryRegion? in
        let memory = Memory(ptr: ptr, knownSize: sizeof(T.self))
        return memory.map({ MemoryRegion(depth: 1, pointer: ptr, memory: $0) })
    })
    guard let rootRegion = maybeRootRegion else { return [] }
    
    var allRegions: [Pointer: MemoryRegion] = [rootRegion.pointer: rootRegion]
    
    var toScan: Set = [rootRegion]
    while let region = toScan.popFirst() where !region.didScan && region.depth < maxDepth {
        let childPointers = region.memory.scanPointers()
        let childMemories = childPointers.flatMap({ pointerAndOffset -> (PointerAndOffset, Memory)? in
            let memory = Memory(ptr: pointerAndOffset.pointer)
            return memory.map({ (pointerAndOffset, $0) })
        })
        let childRegions = childMemories.map({
            return ($0.0.offset, MemoryRegion(depth: region.depth + 1, pointer: $0.0.pointer!, memory: $0.1))
        })
        for (offset, childRegion) in childRegions {
            let canonicalChild: MemoryRegion
            if let r = allRegions[childRegion.pointer] {
                canonicalChild = r
            } else {
                canonicalChild = childRegion
                allRegions[childRegion.pointer] = canonicalChild
            }
            region.children.append(.init(offset: offset, region: canonicalChild))
            toScan.insert(canonicalChild)
        }
        region.didScan = true
    }
    
    return Array(allRegions.values)
}

func dumpAndOpenGraph<T>(_ value: T) {
    var result = ""
    func line(_ string: String) {
        result += string
        result += "\n"
    }
    
    func graphvizNodeName(region: MemoryRegion) -> String {
        let s = String(region.pointer)
        return "_" + s.substring(from: s.index(s.startIndex, offsetBy: 2))
    }
    
    let regions = buildMemoryRegionTree(value: value, maxDepth: 4)
    
    line("digraph memory_dump_graph {")
    for region in regions {
        let memoryString = hexString(bytes: region.memory.buffer, limit: 32, separator: "\n")
        let labelName: String
        if let symbolName = region.memory.symbolName {
            labelName = symbolName
        } else if region.memory.isMalloc {
            labelName = "malloc"
        } else {
            labelName = "unknown"
        }
        let label = "\(labelName) \(region.pointer) (\(region.memory.buffer.count) bytes)\n\(memoryString)"
        line("\(graphvizNodeName(region: region)) [label=\"\(label)\"]")
        
        for child in region.children {
            line("\(graphvizNodeName(region: region)) -> \(graphvizNodeName(region: child.region)) [label=\"@\(child.offset)\"]")
        }
    }
    line("}")
    
    try! result.write(toFile: "/tmp/memorydump.dot", atomically: false, encoding: .utf8)
    NSWorkspace.shared().openFile("/tmp/memorydump.dot", withApplication: "Graphviz")
}

class C: NSObject {
    let z = D()
    let x = 42
    let y = "hello"
}

class D {}

func main() {
    let c = C()
    dumpAndOpenGraph(c)
}

main()
