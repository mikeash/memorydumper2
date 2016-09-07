
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
    return demangleCpp(demangleSwift(string))
}

func demangleSwift(_ string: String) -> String {
    return demangle(string, tool: ["swift-demangle"])
}

func demangleCpp(_ string: String) -> String {
    return demangle(string, tool: ["c++filt", "-n"])
}

func demangle(_ string: String, tool: [String]) -> String {
    let task = Process()
    task.launchPath = "/usr/bin/xcrun"
    task.arguments = tool
    
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

enum DumpOptions {
    case all
    case some(Set<String>)
    case getAvailable((String) -> Void)
    
    static let processOptions: DumpOptions = {
        let parameters = CommandLine.arguments.dropFirst()
        if parameters.count == 0 {
            print("Available dumps are listed here. Pass the desired dumps as arguments, or pass \"all\" to dump all available:")
            return .getAvailable({ print($0) })
        } else if parameters == ["all"] {
            return .all
        } else if parameters == ["prompt"] {
            print("Enter the dump to run:")
            guard let line = readLine(), !line.isEmpty else {
                print("You must enter something. Available dumps:")
                return .getAvailable({ print($0) })
            }
            return line == "all" ? .all : .some([line])
        } else {
            return .some(Set(parameters))
        }
    }()
}

func dumpAndOpenGraph(dumping ptr: UnsafeRawPointer, knownSize: UInt?, maxDepth: Int, filename: String) {
    switch DumpOptions.processOptions {
    case .all:
        break
    case .some(let selected):
        if !selected.contains(filename) {
            return
        }
    case .getAvailable(let callback):
        callback(filename)
        return
    }
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
    line("graph [bgcolor=black]")
    for region in regions {
        let memoryString = hexString(bytes: region.memory.buffer, limit: 64, separator: "\n")
        let labelName: String
        if let className = objcClassName(ptr: region.pointer) {
            labelName = "ObjC class \(demangle(className))"
        } else if let className = objcInstanceClassName(ptr: region.pointer) {
            labelName = "Instance of \(demangle(className))"
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
        
        line("\(graphvizNodeName(region: region)) [style=filled] [fillcolor=white] [label=\"\(escaped)\"]")
        
        for child in region.children {
            line("\(graphvizNodeName(region: region)) -> \(graphvizNodeName(region: child.region)) [color=white] [fontcolor=white] [label=\"@\(child.offset)\"]")
        }
    }
    line("}")
    
    let path = "/tmp/\(filename).dot"
    try! result.write(toFile: path, atomically: false, encoding: .utf8)
    NSWorkspace.shared().openFile(path, withApplication: "Graphviz")
}

func dumpAndOpenGraph<T>(dumping value: T, maxDepth: Int, filename: String) {
    var value = value
    dumpAndOpenGraph(dumping: &value, knownSize: UInt(MemoryLayout<T>.size), maxDepth: maxDepth, filename: filename)
}

func dumpAndOpenGraph(dumping object: AnyObject, maxDepth: Int, filename: String) {
    dumpAndOpenGraph(dumping: unsafeBitCast(object, to: UnsafeRawPointer.self), knownSize: nil, maxDepth: maxDepth, filename: filename)
}


// Dumping of sample objects follows from here.

protocol P {
    func f()
    func g()
    func h()
}

struct EmptyStruct {}
dumpAndOpenGraph(dumping: EmptyStruct(), maxDepth: 60, filename: "Empty struct")

class EmptyClass {}
dumpAndOpenGraph(dumping: EmptyClass(), maxDepth: 60, filename: "Empty class")

class EmptyObjCClass: NSObject {}
dumpAndOpenGraph(dumping: EmptyObjCClass(), maxDepth: 60, filename: "Empty ObjC Class")

struct SimpleStruct {
    var x: Int = 1
    var y: Int = 2
    var z: Int = 3
}
dumpAndOpenGraph(dumping: SimpleStruct(), maxDepth: 60, filename: "Simple struct")

class SimpleClass {
    var x: Int = 1
    var y: Int = 2
    var z: Int = 3
}
dumpAndOpenGraph(dumping: SimpleClass(), maxDepth: 60, filename: "Simple class")

struct StructWithPadding {
    var a: UInt8 = 1
    var b: UInt8 = 2
    var c: UInt8 = 3
    var d: UInt16 = 4
    var e: UInt8 = 5
    var f: UInt32 = 6
    var g: UInt8 = 7
    var h: UInt64 = 8
}
dumpAndOpenGraph(dumping: StructWithPadding(), maxDepth: 60, filename: "Struct with padding")

class ClassWithPadding {
    var a: UInt8 = 1
    var b: UInt8 = 2
    var c: UInt8 = 3
    var d: UInt16 = 4
    var e: UInt8 = 5
    var f: UInt32 = 6
    var g: UInt8 = 7
    var h: UInt64 = 8
}
dumpAndOpenGraph(dumping: ClassWithPadding(), maxDepth: 60, filename: "Class with padding")

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
dumpAndOpenGraph(dumping: DeepClass(), maxDepth: 60, filename: "Deep class")

dumpAndOpenGraph(dumping: [1, 2, 3, 4, 5], maxDepth: 4, filename: "Integer array")

struct StructSmallP: P {
    func f() {}
    func g() {}
    func h() {}
    var a = 0x6c6c616d73
}
struct StructBigP: P {
    func f() {}
    func g() {}
    func h() {}
    var a = 0x746375727473
    var b = 0x1010101010101010
    var c = 0x2020202020202020
    var d = 0x3030303030303030
}
struct ClassP: P {
    func f() {}
    func g() {}
    func h() {}
    var a = 0x7373616c63
    var b = 0x4040404040404040
    var c = 0x5050505050505050
    var d = 0x6060606060606060
}
struct ProtocolHolder {
    var a: P
    var b: P
    var c: P
}
let holder = ProtocolHolder(a: StructSmallP(), b: StructBigP(), c: ClassP())
dumpAndOpenGraph(dumping: holder, maxDepth: 4, filename: "Protocol types")

DumpCMemory({ (pointer: UnsafeRawPointer?, knownSize: Int, maxDepth: Int, name: UnsafePointer<Int8>?) in
    dumpAndOpenGraph(dumping: pointer!, knownSize: UInt(knownSize), maxDepth: maxDepth, filename: String(cString: name!))
})
