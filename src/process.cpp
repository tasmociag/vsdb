#include <libvsdb/process.hpp>
#include <libvsdb/error.hpp>
#include <dbghelp.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <optional>
#include <variant>
#include <codecvt>
#include <filesystem>

#include "PDB_RawFile.h"
#include "PDB_DBIStream.h"
#include "PDB_PublicSymbolStream.h"
#include "PDB_ImageSectionStream.h"
#include "PDB_CoalescedMSFStream.h"
#include "PDB_ErrorCodes.h"
#include "PDB_DBITypes.h"


vsdb::process::module::module(uint64_t ba, std::string mn, process& p): baseAddress_(ba), moduleName_(mn), parent_(p){
    dosHeader_ = parent_.bytesToData<IMAGE_DOS_HEADER>(baseAddress_);
    uint64_t peHeaderAddress = baseAddress_+dosHeader_.e_lfanew;
    peHeader_ = parent_.bytesToData<IMAGE_NT_HEADERS64>(peHeaderAddress);
    moduleSize_ = peHeader_.OptionalHeader.SizeOfImage;

    readExportTableDirectory();
    readDebugDirecotry();

    printModuleInformations();
}

void vsdb::process::module::readExportTableDirectory(){
    IMAGE_DATA_DIRECTORY exportTableSource = peHeader_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    std::cout << "Export Table RVA: 0x" << std::hex << exportTableSource.VirtualAddress << " Size: 0x" << exportTableSource.Size << "\n";
    if(exportTableSource.VirtualAddress!=0){
        uint64_t exportTableBaseAddress = baseAddress_ + exportTableSource.VirtualAddress;
        uint64_t exportTableEndAddress = exportTableBaseAddress + exportTableSource.Size;

        IMAGE_EXPORT_DIRECTORY exportTable = parent_.bytesToData<IMAGE_EXPORT_DIRECTORY>(exportTableBaseAddress);
        
        if(exportTable.Name!=0){
            uint64_t moduleNameAddress = baseAddress_+exportTable.Name;
            moduleName_ = parent_.bytesToString(moduleNameAddress, 512, false);
        }

        uint64_t functionsAddressesTableAddress = baseAddress_ + exportTable.AddressOfFunctions;
        std::vector<uint32_t> functionsAddressesTable = parent_.bytesToArray<uint32_t>(functionsAddressesTableAddress, exportTable.NumberOfFunctions);

        uint64_t ordinalsNameTableAddress = baseAddress_ + exportTable.AddressOfNameOrdinals;
        std::vector<uint16_t> ordinalsNameTable = parent_.bytesToArray<uint16_t>(ordinalsNameTableAddress, exportTable.NumberOfNames);
        uint64_t namesNameTableAddress = baseAddress_ + exportTable.AddressOfNames ;
        std::vector<uint32_t> namesNameTable = parent_.bytesToArray<uint32_t>(namesNameTableAddress, exportTable.NumberOfNames);
        std::cout << std::dec << "loaded ordinalTable size: " << ordinalsNameTable.size() << "\n";
        std::cout << std::dec << "loaded namesTable size: " << namesNameTable.size() << "\n";
        std::cout << std::dec << "exportTable.Base: " << exportTable.Base << "\n";

        for(int functionIndex=0;functionIndex<functionsAddressesTable.size();functionIndex++){
            uint64_t exportFunctionAddress = baseAddress_ + functionsAddressesTable[functionIndex];
            uint32_t ordinalIndex = exportTable.Base + functionIndex;

            int64_t indexNameTable = -1; 
            for(int ordinalTableIndex = 0;ordinalTableIndex<ordinalsNameTable.size();ordinalTableIndex++){
                if(ordinalsNameTable[ordinalTableIndex] == functionIndex){
                    indexNameTable=ordinalTableIndex;
                    break;
                }
            }
            
            std::string exportName = "*name stripped*";
            if(indexNameTable != -1){
                uint64_t nameAdress = baseAddress_+namesNameTable[indexNameTable];
                exportName = parent_.bytesToString(nameAdress,256,false);
            }

            if(exportFunctionAddress >= exportTableBaseAddress && exportFunctionAddress < exportTableEndAddress){
                std::string forwardingName = parent_.bytesToString(exportFunctionAddress,256, false);
                exports_.push_back(std::make_unique<vsdb::process::module::exportItem>(vsdb::process::module::exportItem{exportName, ordinalIndex, forwardingName}));
            }else{
                exports_.push_back(std::make_unique<vsdb::process::module::exportItem>(vsdb::process::module::exportItem{exportName, ordinalIndex, exportFunctionAddress}));
            }
        }
    }
}

void vsdb::process::module::readPdbSymbols(const std::wstring& pdbPath)
{
    mappedFile mapped{};

    mapped.file = CreateFileW(pdbPath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (mapped.file == INVALID_HANDLE_VALUE)
        vsdb::error::send("CreateFileW failed");

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(mapped.file, &size))
        vsdb::error::send("GetFileSizeEx failed");

    mapped.size = static_cast<std::size_t>(size.QuadPart);

    mapped.mapping = CreateFileMappingW(mapped.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapped.mapping)
        vsdb::error::send("CreateFileMappingW failed");

    mapped.view = MapViewOfFile(mapped.mapping, FILE_MAP_READ, 0, 0, 0);
    if (!mapped.view)
        vsdb::error::send("MapViewOfFile failed");

    
    PDB::RawFile rawPdb(mapped.view);
    std::cout << "2. created RawPDB view\n";

    if (PDB::HasValidDBIStream(rawPdb) != PDB::ErrorCode::Success)
        vsdb::error::send("PDB has no valid DBI stream");

    PDB::DBIStream dbi = PDB::CreateDBIStream(rawPdb);

    const PDB::ImageSectionStream imageSections = dbi.CreateImageSectionStream(rawPdb);
    const PDB::PublicSymbolStream publicStream = dbi.CreatePublicSymbolStream(rawPdb);
    const PDB::CoalescedMSFStream symbolRecords = dbi.CreateSymbolRecordStream(rawPdb);
    std::cout << "4. created DBI streams\n";
    const auto hashRecords = publicStream.GetRecords();

    using Kind = PDB::CodeView::DBI::SymbolRecordKind;

    for (const PDB::HashRecord& hr : hashRecords)
    {
        const auto* rec = publicStream.GetRecord(symbolRecords, hr);
        if (!rec)
            continue;

        if (rec->header.kind != Kind::S_PUB32)
            continue;

        const auto& s = rec->data.S_PUB32;

        std::uint32_t rva =
            imageSections.ConvertSectionOffsetToRVA(s.section, s.offset);

        if (!rva)
            continue;
            
        pdbSymbols_.push_back(std::make_unique<vsdb::process::module::pdbSymbol>(vsdb::process::module::pdbSymbol{ s.name, baseAddress_+rva }));
    }
}

void vsdb::process::module::readDebugDirecotry(){
    IMAGE_DATA_DIRECTORY debugDirectorySourceInfo = peHeader_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if(debugDirectorySourceInfo.VirtualAddress!=0){
        uint64_t debugDirectoryStructSize = sizeof(IMAGE_DEBUG_DIRECTORY);
        uint64_t debugDirectoryTableSize = min(debugDirectorySourceInfo.Size / debugDirectoryStructSize, debugDirectoryDataLimit_);
        for(int debugDirectoryIndex = 0; debugDirectoryIndex<debugDirectoryTableSize;debugDirectoryIndex++){
            uint64_t debugDirectoryDataAddress =  baseAddress_ + debugDirectorySourceInfo.VirtualAddress + (debugDirectoryIndex*debugDirectoryStructSize);
            IMAGE_DEBUG_DIRECTORY debugDirectory = parent_.bytesToData<IMAGE_DEBUG_DIRECTORY>(debugDirectoryDataAddress);
            if(debugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW){
                uint64_t ddCodeviewAddress = baseAddress_+debugDirectory.AddressOfRawData;
                ddCodeview codeviewInfo = parent_.bytesToData<ddCodeview>(ddCodeviewAddress);

                uint64_t codeviewNameAddress = ddCodeviewAddress+sizeof(ddCodeview);
                std::string codeviewName = parent_.bytesToString(codeviewNameAddress, 256,false);

                if (!std::filesystem::exists(codeviewName)) {
                    continue;
                }

                readPdbSymbols(std::wstring(codeviewName.begin(), codeviewName.end()));
            }

        }
    }
}

bool vsdb::process::module::containsAddress(uint64_t address){
    uint64_t endAddress = baseAddress_+moduleSize_;
    return (address>=baseAddress_ && address<endAddress);
}

void vsdb::process::module::printModuleInformations(){
    std::cout << "LoadDll: 0x" << std::hex << baseAddress_ << "    " << moduleName_ << "\n";
}



vsdb::process::breakpointController::breakpointController(process& p): parent_(p){
    breakpoints_.clear();
}

void vsdb::process::breakpointController::addBreakpoint(uint64_t address) {
    breakpoints_.push_back({address, nextBreakpointId_});
    nextBreakpointId_++;
}
void vsdb::process::breakpointController::removeBreakpoint(uint16_t id) {
    for(int i=0;i<breakpoints_.size();i++){
        if(breakpoints_[i].id == id){
            breakpoints_.erase(breakpoints_.begin()+i);
            return;
        }
    }
}

std::vector<vsdb::process::breakpointController::breakpoint> vsdb::process::breakpointController::getListOfBreakpoints() {
    return breakpoints_;
}

void vsdb::process::breakpointController::setHardwareBreakpoints(){
    CONTEXT context{};
    context.ContextFlags=CONTEXT_ALL;
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, FALSE, parent_.debugEvent_.dwThreadId);
    if(!hThread){
        vsdb::error::send_errno("OpenThread failed in setHardwareBreakpoints()");
    }

    if(!GetThreadContext(hThread, &context)){
        vsdb::error::send_errno("GetThreadContext failed in setHardwareBreakpoints()");
    }
    
    for(int i=0;i<breakpoints_.size() && i<4;i++){
        breakpoint& bp = breakpoints_[i];
        parent_.setBits<uint64_t>(context.Dr7, 0ULL, DR7_LEN_BITS[i], DR7_LEN_SIZE);
        parent_.setBits<uint64_t>(context.Dr7, 0ULL, DR7_RW_BITS[i], DR7_RW_SIZE);
        parent_.setBits<uint64_t>(context.Dr7, 1ULL, DR7_LE_BITS[i], 1);

        if(i==0) context.Dr0 = bp.address;
        else if(i==1) context.Dr1 = bp.address;
        else if(i==2) context.Dr2 = bp.address;
        else if(i==3) context.Dr3 = bp.address;
    }
    if(!SetThreadContext(hThread, &context)){
        vsdb::error::send_errno("SetThreadContext failed in setHardwareBreakpoints()");
    }
    CloseHandle(hThread);
}



std::unique_ptr<vsdb::process> vsdb::process::launch(std::string path) {
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi;

    std::wstring cmd = std::wstring(path.begin(), path.end());
    wchar_t* cmdW = const_cast<wchar_t*>(cmd.c_str());

    bool success = CreateProcessW(
        nullptr,     
        cmdW,        
        nullptr,      
        nullptr,    
        FALSE,       
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        nullptr,  
        nullptr,     
        &si,         
        &pi         
    );

    if (!success) {vsdb::error::send_errno("CreateProcess failed");}

    std::unique_ptr<process> processPtr(new process(pi.dwProcessId, false));
    processPtr->state_ = vsdb::process_state::initialized;
    return processPtr;
}

std::unique_ptr<vsdb::process> vsdb::process::attach(DWORD pid) {
    bool success = DebugActiveProcess(pid);

    if (!success) {vsdb::error::send_errno("Failed to attach to process " + std::to_string(pid));}

    std::unique_ptr<process> processPtr(new process(pid, true));
    processPtr->state_ = vsdb::process_state::initialized;
    
    return processPtr;
}


std::vector<std::string> vsdb::process::split(const std::string_view str, char delimiter){
        std::vector<std::string> result;
        size_t start = 0;
        size_t end = str.find(delimiter);
        while (end != std::string_view::npos) {
            result.push_back(std::string(str.substr(start, end - start)));
            start = end + 1;
            end = str.find(delimiter, start);
        }
        result.push_back(std::string(str.substr(start)));
        return result;
}

void vsdb::process::sendCommand(const std::string& command) {
    std::vector<std::string> args = split(command, ' ');

    if(args[0] == "p" || args[0] == "print"){
        commandPrint(args);
    }else if(args[0] == "c" || args[0] == "continue"){
        commandContinue(args);
    }else if(args[0] == "si" || args[0] == "stepinto"){
        commandStepInto(args);
    }else if(args[0] == "q" || args[0] == "quit"){
        commandQuit(args);
    }else if(args[0] == "r" || args[0] == "run"){
        commandRun(args);
    }else if(args[0] == "rs" || args[0] == "resolveaddress"){
        commandResolveSymbol(args);
    }else if(args[0] == "ra" || args[0] == "resolvesymbol"){
        commandResolveAddress(args);
    }else if(args[0] == "b" || args[0] == "breakpoint"){
        commandBreakpoint(args);
    }else if(args[0] == "bi" || args[0] == "breakpointinfo"){
        commandBreakpointInfo(args);
    }else if(args[0] == "br" || args[0] == "breakpointremove"){
        commandBreakpointRemove(args);
    }else if(args[0] == "h" || args[0] == "help"){
        if(args.size() > 1){
            commandHelp(args[1]);
        }else{
            commandHelp("");
        }
    }
}


std::vector<std::optional<uint8_t>> vsdb::process::examinMemory(uint64_t address, size_t count){

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid_);
    if (!hProc) {
        vsdb::error::send("OpenProcess failed: " + std::to_string(GetLastError()));
    }

    std::vector<std::optional<uint8_t>> result;
    for(int32_t i=0;i<count;i++){
        uint8_t value{};
        SIZE_T bytesRead = 0;
        BOOL ok = ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(address+i), &value, 1, &bytesRead);
        if (!ok || bytesRead != 1) {\
            result.push_back(std::nullopt);
        }else{
            result.push_back(value);
        }
    }

    CloseHandle(hProc);
    return result;
}

template <typename T>
T vsdb::process::bytesToData(uint64_t address) {
    std::vector<std::optional<uint8_t>> bytes = vsdb::process::examinMemory(address, sizeof(T));
    for (auto& b : bytes) {
        if (!b.has_value()) {
            vsdb::error::send("empty value from examinMemory in bytesToData()");
        }
    }

    T value{};
    uint8_t* dest = reinterpret_cast<uint8_t*>(&value);
    for (size_t i = 0; i < sizeof(T); ++i) {
        dest[i] = *bytes[i];
    }

    return value;
}

template <typename T>
std::vector<T> vsdb::process::bytesToArray(uint64_t address, size_t maxCount) {
    size_t totalBytes = sizeof(T) * maxCount;
    std::vector<std::optional<uint8_t>> bytes = vsdb::process::examinMemory(address, totalBytes);

    if (bytes.size() != totalBytes) {
        vsdb::error::send("bytesToArray(): examinMemory returned wrong size ");
    }
    for (auto& b : bytes) {
        if (!b.has_value()) {
            vsdb::error::send("empty value from examinMemory in bytesToArray()");
        }
    }

    std::vector<T> result;
    result.reserve(maxCount);

    for (size_t i = 0; i < maxCount; ++i) {
        T item{};
        uint8_t* dest = reinterpret_cast<uint8_t*>(&item);
        for (size_t b = 0; b < sizeof(T); ++b) {
            dest[b] = *bytes[i * sizeof(T) + b];
        }

        result.push_back(item);
    }

    return result;
}

std::string vsdb::process::bytesToString(uint64_t address, size_t maxCount, bool isWide) {
if (isWide) {
        // Read UTF-16 (wide) string
        std::vector<std::optional<uint8_t>> bytes = vsdb::process::examinMemory(address, maxCount * sizeof(wchar_t));
        std::wstring wideStr;
        for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
            if (!bytes[i] || !bytes[i + 1]) break;
            wchar_t ch = static_cast<wchar_t>(*bytes[i] | (*bytes[i + 1] << 8));
            if (ch == L'\0') break;
            wideStr.push_back(ch);
        }

        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
        return conv.to_bytes(wideStr);
    } else {
        // Read ASCII / UTF-8 string
        std::vector<std::optional<uint8_t>> bytes = vsdb::process::examinMemory(address, maxCount);
        std::string result;
        for (auto& b : bytes) {
            if (!b || *b == 0) break;
            result.push_back(static_cast<char>(*b));
        }

        return result;
    }
}


template <typename T>
void vsdb::process::setBits(T& val, T set_val, std::size_t start_bit, std::size_t bit_count) {
    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer type");

    const std::size_t max_bits = sizeof(T) * 8;

    T mask = (std::numeric_limits<T>::max)();
    mask <<= (max_bits - bit_count);
    mask >>= (max_bits - 1 - start_bit);
    
    T inv_mask = ~mask;
    val &= inv_mask;
    val |= (set_val << (start_bit + 1 - bit_count));
}

uint64_t vsdb::process::resolveSymbolToAddress(std::string symbolName){
    for(auto& mod : modules_){
        for(auto& exp : mod->exports_){
            if(exp->name == symbolName){
                if(std::holds_alternative<uint64_t>(exp->address)){
                    return std::get<uint64_t>(exp->address);
                }else{
                    std::cout << "Symbol " + symbolName + " is forwarded, cannot resolve to address\n";
                }
            }
        }
        for(auto& pdbSym : mod->pdbSymbols_){
            if(pdbSym->name == symbolName){
                return pdbSym->address;
            }
        }
    }
    std::cout << "Symbol " + symbolName + " not found in loaded modules\n";
    return 0;
}



std::string vsdb::process::resolveAddressToSymbol(uint64_t address){
    vsdb::process::module* correctModule = getContainingModule(address);
    if(!correctModule){return "*no symbol*";}
    
    uint64_t closestExportAddress=0;
    vsdb::process::module::exportItem* closestExport=nullptr; 
    for(auto& exp : correctModule->exports_){
        if(std::holds_alternative<uint64_t>(exp->address)){
            uint64_t testAddress = std::get<uint64_t>(exp->address);

            if(testAddress <= address){
                if(closestExportAddress==0 || closestExportAddress<testAddress){
                    closestExportAddress=testAddress;
                    closestExport = exp.get();
                }
            }
        }
    }
    vsdb::process::module::pdbSymbol* closestPdbSymbol = nullptr;
    if(closestExport==nullptr){
        for(auto& symbol : correctModule->pdbSymbols_){
            if(symbol->address <= address){
                if(closestExportAddress==0 || closestExportAddress<symbol->address){
                    closestExportAddress=symbol->address;
                    closestPdbSymbol = symbol.get();
                }
            }
        }
    }
    
    
    std::stringstream resultSymbol;
    if(closestExport!=nullptr || closestPdbSymbol!=nullptr){
        uint64_t offset = address-closestExportAddress;
        std::string symbolName;
        if(closestExport!=nullptr){
            symbolName = closestExport->name;
        }else{
            symbolName = closestPdbSymbol->name;
        }
        if(offset == 0){
            resultSymbol << correctModule->moduleName_ << "->" << symbolName;
        }else{
            resultSymbol << correctModule->moduleName_ << "->" << symbolName << "+" << std::hex << offset;
        }
    }else{
        resultSymbol << correctModule->moduleName_ << "!unknown";
    }
    return resultSymbol.str();
}

vsdb::process::module* vsdb::process::getContainingModule(uint64_t address){
    for (auto& mod : modules_) {
        if (mod->containsAddress(address)) {
            return mod.get();
        }
    }
    return nullptr;
}

void vsdb::process::handleOutputDebugStringEvent(){
    std::cout << "OutputDebugString: ";
    
    const OUTPUT_DEBUG_STRING_INFO& info = debugEvent_.u.DebugString;

    bool isWide = info.fUnicode;
    uint64_t address = reinterpret_cast<uint64_t>(info.lpDebugStringData);
    size_t length = info.nDebugStringLength;

    std::vector<std::optional<uint8_t>> buffer = examinMemory(address, length);
    displayData(buffer, "S", 0, isWide);
    return;
}

void vsdb::process::handleLoadDllDebugEvent(){

    const LOAD_DLL_DEBUG_INFO& info = debugEvent_.u.LoadDll;

    uint64_t baseDll = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
    std::string moduleName = "";

    if(info.lpImageName != nullptr){
        uint64_t nameAddress = reinterpret_cast<uint64_t>(info.lpImageName);
        uint64_t stirngNamePointerAddress = vsdb::process::bytesToData<uint64_t>(nameAddress);
        moduleName = vsdb::process::bytesToString(stirngNamePointerAddress, 260, info.fUnicode);
        std::cout << "LoadDll: " << moduleName << "\n";
    }
    modules_.push_back(std::make_unique<vsdb::process::module>(vsdb::process::module{baseDll,moduleName,*this}));
}

void vsdb::process::handleCreateProcessDebugEvent(){
    const CREATE_PROCESS_DEBUG_INFO& info = debugEvent_.u.CreateProcessInfo;
    uint64_t baseAddress = reinterpret_cast<uint64_t>(info.lpBaseOfImage);

    std::wstring exeName(260, L'\0');
    DWORD exeNameLen = GetFinalPathNameByHandleW(info.hFile, exeName.data(), static_cast<DWORD>(exeName.size()),0);

    if (exeNameLen > 0 && exeNameLen < exeName.size()) {
        exeName.resize(exeNameLen);
    }

    std::string moduleName = std::string(exeName.begin(), exeName.end());
    std::cout << "CreateProcess: " << moduleName << "\n";
    modules_.push_back(std::make_unique<vsdb::process::module>(vsdb::process::module{baseAddress,moduleName,*this}));
}

void vsdb::process::handleExceptionDebugEvent(){
    std::cout << "ExceptionDebugEvent: Breakpoint hit!!!!";
    setBits<DWORD>(ctx_.EFlags, 1ULL, 16, 1);
    if(!SetThreadContext(hThread_, &ctx_)){
        vsdb::error::send_errno("SetThreadContext failed in handleExceptionDebugEvent()");
    }
}

bool vsdb::process::runAndWaitForDebugEvent() {

    if(state_ != vsdb::process_state::initialized){
        if (hThread_) { 
            CloseHandle(hThread_); 
            hThread_ = nullptr; 
        }
        ctx_ = CONTEXT{}; 
        ctx_.ContextFlags = 0;

        breakpointController_.setHardwareBreakpoints();
        ContinueDebugEvent(debugEvent_.dwProcessId, debugEvent_.dwThreadId, DBG_CONTINUE);
    }

    if(state_ == vsdb::process_state::exited || state_ == vsdb::process_state::terminated){
        vsdb::error::send("Process has already exited or terminated.");
        return false;
    }
    // while(true){
    if (WaitForDebugEvent(&debugEvent_, INFINITE)) {
        hThread_ = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, FALSE, debugEvent_.dwThreadId);
        if (!hThread_) {
            vsdb::error::send("OpenThread failed for TID " + std::to_string(debugEvent_.dwThreadId));
            return false;
        }

        ctx_.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(hThread_, &ctx_)) {
            vsdb::error::send_errno("GetThreadContext failed (x64) for TID " + std::to_string(debugEvent_.dwThreadId));
            CloseHandle(hThread_);
            return false;
        }

        switch (debugEvent_.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                handleExceptionDebugEvent();
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                std::cout << "CreateThread" << std::endl;
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                state_ = vsdb::process_state::stopped;
                handleCreateProcessDebugEvent();
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                std::cout << "ExitThread" << std::endl;
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                std::cout << "ExitProcess" << std::endl;
                vsdb::error::send("Process exited, stopping debug loop");
                state_ = vsdb::process_state::exited;
                return false;
                break;
            case LOAD_DLL_DEBUG_EVENT:
                handleLoadDllDebugEvent();
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                std::cout << "UnloadDll" << std::endl;
                break;
            case OUTPUT_DEBUG_STRING_EVENT: {
                handleOutputDebugStringEvent();
                break;
            }
            case RIP_EVENT:
                std::cout << "RipEvent" << std::endl;
                break;
            default:
                throw std::runtime_error("Unexpected debug event");
        }

        state_ = vsdb::process_state::stopped;
    } else {
        vsdb::error::send_errno("Failed to wait for debug event.");
        return false;   
    }
    return true;
}

uint64_t vsdb::process::stringToUint64(const std::string str){
    int base = 10;
    std::size_t start = 0;
 
    if (str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
        start = 2;
    }

    try {
        return std::stoull(str.substr(start), nullptr, base);
    } catch (const std::invalid_argument&) {
        throw std::invalid_argument("Invalid numeric string: " + str);
    } catch (const std::out_of_range&) {
        throw std::out_of_range("Value out of range for uint64_t: " + str);
    }
}

uint64_t vsdb::process::getRegister(std::string reg){
    if (reg.empty()) {
        vsdb::error::send("Empty register reg");
        return {};
    }

    if (reg == "rax") return ctx_.Rax;
    if (reg == "rbx") return ctx_.Rbx;
    if (reg == "rcx") return ctx_.Rcx;
    if (reg == "rdx") return ctx_.Rdx;
    if (reg == "rsi") return ctx_.Rsi;
    if (reg == "rdi") return ctx_.Rdi;
    if (reg == "rsp") return ctx_.Rsp;
    if (reg == "rbp") return ctx_.Rbp;
    if (reg == "rip") return ctx_.Rip;
    if (reg == "r8")  return ctx_.R8;
    if (reg == "r9")  return ctx_.R9;
    if (reg == "r10") return ctx_.R10;
    if (reg == "r11") return ctx_.R11;
    if (reg == "r12") return ctx_.R12;
    if (reg == "r13") return ctx_.R13;
    if (reg == "r14") return ctx_.R14;
    if (reg == "r15") return ctx_.R15;

    vsdb::error::send("Unknown register: " + (reg));
    return {};
}

std::string vsdb::process::getBreakInfo(){
    uint64_t address = getRegister("rip");
    std::ostringstream  inputLine;
    inputLine << "{rip}[0x" << std::hex << address << "] " << resolveAddressToSymbol(address) << " ";
    return inputLine.str();
}

void vsdb::process::displayData(std::vector<std::optional<uint8_t>> data, std::string type, uint64_t startingAddress, bool isWide){
    if( type == "S"){
        std::string byteString;
        byteString.reserve(data.size());
        for (int i=0;i<data.size();i++) {
            if (!data[i].has_value()){break;}
            if(isWide && i>0 && static_cast<uint8_t>(*data[i])==0 && static_cast<uint8_t>(*data[i-1])==0){break;}
            if(!isWide && static_cast<uint8_t>(*data[i])==0){break;}
            byteString.push_back(static_cast<char>(*data[i]));
        }

        if (isWide) {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::wstring wideStr;
            try {
                wideStr = converter.from_bytes(byteString);
            } catch (const std::range_error&) {
                std::wcerr << L"[Error: invalid Unicode sequence]" << std::endl;
                return;
            }

            std::wcout << wideStr << std::endl;
        } else {
            std::cout << byteString << std::endl;
        }
    }else{
        uint32_t dataSize = 0;
        if(type == "B"){dataSize = 1;}
        if(type == "W"){dataSize = 2;}
        if(type == "DW"){dataSize = 4;}
        if(type == "QW"){dataSize = 8;}

        uint32_t lineSize = 16/dataSize;

        uint64_t displayValue=0;
        bool isPartial = false;
        for (size_t i = 0; i < data.size(); i++) {
            if (data[i].has_value()) {
                uint64_t val = static_cast<uint64_t>(*data[i]);
                val<<=8*(i%dataSize);
                displayValue |= val;
            }else{
                isPartial=1;
            }
            if((i+1)%dataSize==0){
                if (!isPartial) {
                    if (((i+1)/dataSize) % lineSize == 1) {
                        std::cout << std::hex << startingAddress + ((i+1)/dataSize) - 1 << ":  ";
                    } 
                    std::cout << std::hex << std::showbase << static_cast<uint64_t>(displayValue) << " ";

                    if(i==data.size()-1 || ((i+1)/dataSize) % lineSize == 0){std::cout << "\n";}
                } else {
                    if (((i+1)/dataSize) % lineSize == 1) {
                        std::cout << std::hex << startingAddress + (i/2)*8 << ":  ";
                    } 
                    std::cout << "invalid ";

                    if(i==data.size()-1 || ((i+1)/dataSize) % lineSize == 0){std::cout << "\n";}
                }
                isPartial=0;
                displayValue=0;
            }
        }
    }
}

void vsdb::process::commandHelp(std::string command){
    if(command == "print" || command == "p"){
        std::cout << "Usage: print/p [*&address] [size] [type]\n\t[*&address] = *-memory address, &-register address\n\t[size] = length of data to read\n\t[type] = data type [B,W,DW,QW,S] -> (Byte, Word, Double Word, Quad Word, String)\n";
    }else if(command == "continue" || command == "c"){
        std::cout << "Usage: continue/c\n";
    }else if(command == "stepinto" || command == "si"){
        std::cout << "Usage: stepinto/si\n";
    }else if(command == "run" || command == "r"){
        std::cout << "Usage: run/r\n";
    }else if(command == "quit" || command == "q"){
        std::cout << "Usage: quit/q\n";
    }else if(command == "resolveaddress" || command == "rs"){
        std::cout << "Usage: resolveaddress/rs [address]\n";
    }else if(command == "resolvesymbol" || command == "ra"){
        std::cout << "Usage: resolvesymbol/ra [symbolname]\n";
    }else if(command == "breakpoint" || command == "b"){
        std::cout << "Usage: breakpoint/b [address]\n";
    }else if(command == "breakpointinfo" || command == "bi"){
        std::cout << "Usage: breakpointinfo/bi\n";
    }else if(command == "breakpointremove" || command == "br"){
        std::cout << "Usage: breakpointremove/br [address]\n"; 
    }else if(command == ""){
        std::cout << "Available commands:\n";
        std::cout << "print/p, continue/c, stepinto/si, run/r, quit/q, resolveaddress/rs, resolvesymbol/ra, breakpoint/b, breakpointinfo/bi, breakpointremove/br\n";
        std::cout << "Type 'help [command]' for more information on a specific command.\n";
    }
}

void vsdb::process::commandPrint(std::vector<std::string> args){   
    if(args.size() == 1){
        std::cout << "RAX: " << std::hex << ctx_.Rax << " RBX: " << ctx_.Rbx << " RCX: " << ctx_.Rcx << std::endl;
        std::cout << "RDX: " << std::hex << ctx_.Rdx << " RSI: " << ctx_.Rsi << " RDI: " << ctx_.Rdi << std::endl;
        std::cout << "R8 : " << std::hex << ctx_.R8  << " R9 : " << ctx_.R9  << " R10: " << ctx_.R10 << std::endl;
        std::cout << "R11: " << std::hex << ctx_.R11 << " R12: " << ctx_.R12 << " R13: " << ctx_.R13 << std::endl;
        std::cout << "R14: " << std::hex << ctx_.R14 << " R15: " << ctx_.R15 << std::endl;
        std::cout << "RIP: " << std::hex << ctx_.Rip << " RSP: " << ctx_.Rsp << " RBP: " << ctx_.Rbp << std::endl;
    }else if(args.size() >= 2){
        if(args[1][0] == '&'){
            std::string registerValue = std::to_string(getRegister(args[1].substr(1)));
            std::cout << registerValue << "\n";
        }else if(args[1][0] == '*'){
            if(args.size()<4){
                std::cout << "p/print [*&]address length [B,W,DW,QW,S]type";
                return;
            }
            std::uint64_t address = stringToUint64(args[1].substr(1));
            std::size_t count = (size_t)stringToUint64(args[2]);
            
            std::vector<std::optional<uint8_t>> data;
            data = examinMemory(address, count);
            displayData(data, args[3], address);
        }
    }else{
        vsdb::error::send("commandPrint: wrong command");
    }

    state_ = vsdb::process_state::stopped;
}

void vsdb::process::commandContinue(std::vector<std::string> args){
    runAndWaitForDebugEvent();
    state_ = vsdb::process_state::running;
}

void vsdb::process::commandStepInto(std::vector<std::string> args){
    ctx_.EFlags |= 0x100;
    if(!SetThreadContext(hThread_, &ctx_)){
        std::cerr << "SetThreadContext failed (x64) for TID " << debugEvent_.dwThreadId << " Error: " << GetLastError() << std::endl;
    }else{
        runAndWaitForDebugEvent();
    }
    expectStep_ = true;
    state_ = vsdb::process_state::running;    
}

void vsdb::process::commandRun(std::vector<std::string> args){
    bool result = runAndWaitForDebugEvent();
    if(!result){
        vsdb::error::send("runAndWaitForDebugEvent() returned 0");
    }else{
        state_ = vsdb::process_state::running;
    }
}

void vsdb::process::commandResolveAddress(std::vector<std::string> args){
    if(args.size()<2){
        std::cout << "commandResolveAddress: missing address argument\n";
    }
    uint64_t address = stringToUint64(args[1]);
    std::string symbol = resolveAddressToSymbol(address);
    std::cout << symbol << "\n";
    state_ = vsdb::process_state::stopped;
}

void vsdb::process::commandResolveSymbol(std::vector<std::string> args){
    if(args.size()<2){
        std::cout << "commandResolveSymbol: missing symbol name argument\n";
    }
    std::string symbolName = args[1];
    uint64_t address = resolveSymbolToAddress(symbolName);    
    std::cout << "0x" << std::hex << address << "\n";
    state_ = vsdb::process_state::stopped;
}

void vsdb::process::commandBreakpoint(std::vector<std::string> args){
    if(args.size()<2){
        std::cout << "commandBreakpoint: missing address argument\n";
    }
    uint64_t address = resolveSymbolToAddress(args[1]);
    breakpointController_.addBreakpoint(address);
}
void vsdb::process::commandBreakpointInfo(std::vector<std::string> args){
    std::vector<vsdb::process::breakpointController::breakpoint> breakpointsInfo  = breakpointController_.getListOfBreakpoints();
    for(auto& bp : breakpointsInfo){
        std::cout << "Breakpoint ID: " << std::dec << bp.id << " Address: 0x" << std::hex << bp.address << "\n";
    }
}
void vsdb::process::commandBreakpointRemove(std::vector<std::string> args){
    if(args.size()<2){
        std::cout << "commandBreakpointRemove: missing address argument\n";
    }
    breakpointController_.removeBreakpoint(stringToUint64(args[1]));
}

void vsdb::process::commandQuit(std::vector<std::string> args){
    state_ = vsdb::process_state::terminated;
}


vsdb::process::~process(){
    if(isAttached_){
        DebugActiveProcessStop(pid_);
    }else{
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid_);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
    }
}