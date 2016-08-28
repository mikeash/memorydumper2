
import AppKit


struct Pointer {
    var address: UInt
    
    init(_ address: UInt) {
        self.address = address
    }
    
    init(_ ptr: UnsafeRawPointer) {
        address = UInt(bitPattern: ptr)
    }
    
    var voidPtr: UnsafeRawPointer? {
        return UnsafeRawPointer(bitPattern: address)
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
    
    static func ==(lhs: Pointer, rhs: Pointer) -> Bool {
        return lhs.address == rhs.address
    }
    
    static func +(lhs: Pointer, rhs: UInt) -> Pointer {
        return Pointer(lhs.address + rhs)
    }
    
    static func -(lhs: Pointer, rhs: Pointer) -> UInt {
        return lhs.address - rhs.address
    }
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

func demangle(_ string: String) -> String {
    let task = Process()
    task.launchPath = "/usr/bin/xcrun"
    task.arguments = ["swift-demangle"]
    
    let inPipe = Pipe()
    let outPipe = Pipe()
    task.standardInput = inPipe
    task.standardOutput = outPipe
    
    task.launch()
    DispatchQueue.global().async(execute: {
        inPipe.fileHandleForWriting.write(string.data(using: .utf8)!)
        inPipe.fileHandleForWriting.closeFile()
    })
    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8)!
}

extension mach_vm_address_t {
    init(_ ptr: UnsafeRawPointer?) {
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

func hexString<Seq: Sequence>(bytes: Seq, limit: Int? = nil, separator: String = " ") -> String where Seq.Iterator.Element == UInt8 {
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
    let isaBytes = safeRead(ptr: ptr, limit: MemoryLayout<Pointer>.size)
    guard isaBytes.count >= MemoryLayout<Pointer>.size else { return nil }
    
    let isa = isaBytes.withUnsafeBufferPointer({ buffer -> Pointer in
        return buffer.baseAddress!.withMemoryRebound(to: Pointer.self, capacity: 1, { $0.pointee })
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
                return demangle(String(cString: name))
            } else {
                return nil
            }
        })
        
        let length = knownSize ?? symbolLength(ptr: ptr, limit: 4096) ?? mallocLength
        if length > 0 || knownSize == 0 {
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
            return bufferPointer.baseAddress?.withMemoryRebound(to: Pointer.self, capacity: bufferPointer.count / MemoryLayout<Pointer>.size, {
                let castBufferPointer = UnsafeBufferPointer(start: $0, count: bufferPointer.count / MemoryLayout<Pointer>.size)
                return castBufferPointer.enumerated().map({ PointerAndOffset(pointer: $1, offset: $0 * MemoryLayout<Pointer>.size) })
            }) ?? []
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

func buildMemoryRegionTree(ptr: UnsafeRawPointer, knownSize: UInt?, maxDepth: Int) -> [MemoryRegion] {
    let memory = Memory(ptr: Pointer(ptr), knownSize: knownSize)
    let maybeRootRegion = memory.map({ MemoryRegion(depth: 1, pointer: Pointer(ptr), memory: $0) })
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

func dumpAndOpenGraph<T>(dumping value: T, maxDepth: Int, filename: String) {
    var value = value
    dumpAndOpenGraph(dumping: &value, knownSize: UInt(MemoryLayout<T>.size), maxDepth: maxDepth, filename: filename)
}

func dumpAndOpenGraph(dumping ptr: UnsafeRawPointer, knownSize: UInt, maxDepth: Int, filename: String) {
    var result = ""
    func line(_ string: String) {
        result += string
        result += "\n"
    }
    
    func graphvizNodeName(region: MemoryRegion) -> String {
        let s = String(describing: region.pointer)
        return "_" + s.substring(from: s.index(s.startIndex, offsetBy: 2))
    }
    
    let regions = buildMemoryRegionTree(ptr: ptr, knownSize: knownSize, maxDepth: maxDepth)
    
    line("digraph memory_dump_graph {")
    for region in regions {
        let memoryString = hexString(bytes: region.memory.buffer, limit: 64, separator: "\n")
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
    
    let path = "/tmp/\(filename).dot"
    try! result.write(toFile: path, atomically: false, encoding: .utf8)
    NSWorkspace.shared().openFile(path, withApplication: "Graphviz")
}

protocol P {
    func f()
}

func main() {
    struct EmptyStruct {}
    dumpAndOpenGraph(dumping: EmptyStruct(), maxDepth: 60, filename: "EmptyStruct")
    
    class EmptyClass {}
    dumpAndOpenGraph(dumping: EmptyClass(), maxDepth: 60, filename: "EmptyClass")
    
    class EmptyObjCClass: NSObject {}
    dumpAndOpenGraph(dumping: EmptyObjCClass(), maxDepth: 60, filename: "EmptyObjCClass")
    
    struct PrimitivesStruct {
        var a: UInt8 = 10
        var b: UInt32 = 11
        var c: UInt16 = 12
        var d: UInt64 = 13
    }
    dumpAndOpenGraph(dumping: PrimitivesStruct(), maxDepth: 60, filename: "PrimitivesStruct")
    
    class PrimitivesClass {
        var a: UInt8 = 10
        var b: UInt32 = 11
        var c: UInt16 = 12
        var d: UInt64 = 13
    }
    dumpAndOpenGraph(dumping: PrimitivesClass(), maxDepth: 60, filename: "PrimitivesClass")
    
    class DeepClassSuper1 {
        var a = 1
    }
    class DeepClassSuper2: DeepClassSuper1 {
        var b = 2
    }
    class DeepClassSuper3: DeepClassSuper2 {
        var c = 3
    }
    class DeepClass: DeepClassSuper3 {
        var d = 4
    }
    dumpAndOpenGraph(dumping: DeepClass(), maxDepth: 60, filename: "DeepClass")
    
    dumpAndOpenGraph(dumping: [1, 2, 3, 4, 5], maxDepth: 4, filename: "IntegerArray")
    
    struct StructSmallP: P {
        func f() {}
        var a = 0x6c6c616d73
    }
    struct StructBigP: P {
        func f() {}
        var a = 0x746375727473
        var b = 0x1010101010101010
        var c = 0x2020202020202020
        var d = 0x3030303030303030
    }
    struct ClassP: P {
        func f() {}
        var a = 0x7373616c63
        var b = 0x4040404040404040
        var c = 0x5050505050505050
        var d = 0x6060606060606060
    }
    dumpAndOpenGraph(dumping: [StructSmallP(), StructBigP(), ClassP()] as [P], maxDepth: 4, filename: "ProtocolConformance")
    
    DumpCMemory({ (pointer: UnsafeRawPointer?, knownSize: Int, maxDepth: Int, name: UnsafePointer<Int8>?) in
        dumpAndOpenGraph(dumping: pointer!, knownSize: UInt(knownSize), maxDepth: maxDepth, filename: String(cString: name!))
    })
}

main()
