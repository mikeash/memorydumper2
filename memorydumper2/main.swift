
import AppKit


struct Pointer {
    var address: UInt
    
    init(_ address: UInt) {
        self.address = address
    }
    
    init<T>(_ ptr: UnsafePointer<T>) {
        address = UInt(bitPattern: ptr)
    }
    
    init<T>(_ ptr: UnsafeMutablePointer<T>) {
        address = UInt(bitPattern: ptr)
    }
    
    var voidPtr: UnsafePointer<Void>? {
        return UnsafePointer(bitPattern: address)
    }
}

extension Pointer: CustomStringConvertible {
    var description: String {
        return String(format: "%p", address)
    }
}

extension Pointer: Hashable {
    var hashValue: Int {
        return address.hashValue
    }
}

func ==(lhs: Pointer, rhs: Pointer) -> Bool {
    return lhs.address == rhs.address
}

func +(lhs: Pointer, rhs: UInt) -> Pointer {
    return Pointer(lhs.address + rhs)
}

func -(lhs: Pointer, rhs: Pointer) -> UInt {
    return lhs.address - rhs.address
}

func symbolInfo(_ ptr: Pointer) -> Dl_info? {
    var info = Dl_info()
    let result = dladdr(ptr.voidPtr, &info)
    return result == 0 ? nil : info
}

func symbolName(_ ptr: Pointer) -> String? {
    if let info = symbolInfo(ptr) {
        if let symbolAddr = info.dli_saddr, Pointer(symbolAddr) == ptr {
            return String(cString: info.dli_sname)
        }
    }
    return nil
}

func nextSymbol(ptr: Pointer, limit: UInt) -> Pointer? {
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

func symbolLength(ptr: Pointer, limit: UInt) -> UInt? {
    return nextSymbol(ptr: ptr, limit: limit).map({ $0 - ptr })
}

extension mach_vm_address_t {
    init(_ ptr: UnsafePointer<Void>?) {
        self.init(UInt(bitPattern: ptr))
    }
    
    init(_ ptr: Pointer) {
        self.init(ptr.address)
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
        let success = safeRead(ptr: ptr + UInt(buffer.count), into: &eightBytes)
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
        if let limit = limit, index >= limit {
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

func objcClassName(ptr: Pointer) -> String? {
    struct Static {
        static let classMap: [Pointer: AnyClass] = {
            var classCount: UInt32 = 0
            let list = objc_copyClassList(&classCount)!
            
            var map: [Pointer: AnyClass] = [:]
            for i in 0 ..< classCount {
                let classObj: AnyClass = list[Int(i)]!
                let classPtr = unsafeBitCast(classObj, to: Pointer.self)
                map[classPtr] = classObj
            }
            return map
        }()
    }
    
    return Static.classMap[ptr].map({ NSStringFromClass($0) })
}

func objcInstanceClassName(ptr: Pointer) -> String? {
    let isaBytes = safeRead(ptr: ptr, limit: sizeof(Pointer.self))
    guard isaBytes.count >= sizeof(Pointer.self) else { return nil }
    
    let isa = isaBytes.withUnsafeBufferPointer({ buffer -> Pointer in
        let pointerPointer = UnsafePointer<Pointer>(buffer.baseAddress)!
        return pointerPointer.pointee
    })
    return objcClassName(ptr: isa)
}

struct PointerAndOffset {
    var pointer: Pointer
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
    
    init?(ptr: Pointer, knownSize: UInt? = nil) {
        let mallocLength = UInt(malloc_size(ptr.voidPtr))
        
        isMalloc = mallocLength > 0
        symbolName = symbolInfo(ptr).flatMap({
            if let name = $0.dli_sname {
                return String(cString: name)
            } else {
                return nil
            }
        })
        
        let length = knownSize ?? symbolLength(ptr: ptr, limit: 4096) ?? mallocLength
        if length > 0 {
            buffer = Array(repeating: 0, count: Int(length))
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
            let castBufferPointer = UnsafeBufferPointer(start: UnsafePointer<Pointer>(bufferPointer.baseAddress), count: bufferPointer.count / sizeof(Pointer.self))
            return castBufferPointer.enumerated().map({ PointerAndOffset(pointer: $1, offset: $0 * sizeof(Pointer.self)) })
        })
    }
    
    func scanStrings() -> [String] {
        let lowerBound: UInt8 = 32
        let upperBound: UInt8 = 126
        
        let pieces = buffer.split(whereSeparator: { !(lowerBound ... upperBound ~= $0) })
        let sufficientlyLongPieces = pieces.filter({ $0.count >= 4 })
        return sufficientlyLongPieces.map({ String(bytes: $0, encoding: .utf8)! })
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
        let memory = Memory(ptr: Pointer(ptr), knownSize: UInt(sizeof(T.self)))
        return memory.map({ MemoryRegion(depth: 1, pointer: Pointer(ptr), memory: $0) })
    })
    guard let rootRegion = maybeRootRegion else { return [] }
    
    var allRegions: [Pointer: MemoryRegion] = [rootRegion.pointer: rootRegion]
    
    var toScan: Set = [rootRegion]
    while let region = toScan.popFirst() {
        if region.didScan || region.depth >= maxDepth { continue }
        
        let childPointers = region.memory.scanPointers()
        for pointerAndOffset in childPointers {
            let pointer = pointerAndOffset.pointer
            if let existingRegion = allRegions[pointer] {
                existingRegion.depth = min(existingRegion.depth, region.depth + 1)
                region.children.append(.init(offset: pointerAndOffset.offset, region: existingRegion))
                toScan.insert(existingRegion)
            } else if let memory = Memory(ptr: pointer) {
                let childRegion = MemoryRegion(depth: region.depth + 1, pointer: pointer, memory: memory)
                allRegions[pointer] = childRegion
                region.children.append(.init(offset: pointerAndOffset.offset, region: childRegion))
                toScan.insert(childRegion)
            }
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
        if let className = objcClassName(ptr: region.pointer) {
            labelName = "ObjC class \(className)"
        } else if let className = objcInstanceClassName(ptr: region.pointer) {
            labelName = "Instance of \(className)"
        } else if let symbolName = region.memory.symbolName {
            labelName = symbolName
        } else if region.memory.isMalloc {
            labelName = "malloc"
        } else {
            labelName = "unknown"
        }
        
        var label = "\(labelName) \(region.pointer) (\(region.memory.buffer.count) bytes)\n\(memoryString)"
        
        let strings = region.memory.scanStrings()
        if strings.count > 0 {
            label += "\nStrings:\n"
            label += strings.joined(separator: "\n")
        }
        
        let escaped = label
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        
        line("\(graphvizNodeName(region: region)) [label=\"\(escaped)\"]")
        
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
