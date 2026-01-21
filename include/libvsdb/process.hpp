#ifndef SDB_PROCESS_HPP
#define SDB_PROCESS_HPP

#include <windows.h>
#include <memory>
#include <iostream>
#include <vector>
#include <optional>
#include <variant>
#include <unordered_map>

namespace vsdb {
    enum class process_state {
        stopped,
        running,
        exited,
        terminated,
        initialized, 
    };

    

    class process {
    public:
        ~process();

        process() = delete;
        process(const process&) = delete;
        process& operator=(const process&) = delete;
        
        static std::unique_ptr<process> launch(std::string path);
        static std::unique_ptr<process> attach(DWORD pid);

        
        void sendCommand(const std::string& command);

        std::string getBreakInfo();

        process_state getState() const { return state_;}
        DWORD getPid() const { return pid_; }
        // std::string getRegister(std::string req);
        uint64_t getRegister(std::string req);


        bool isInitialized() const { return state_ == process_state::initialized; }

    private:
        class module {
        public:
            struct exportItem{
                std::string name; 
                uint64_t ordinal;
                std::variant<uint64_t, std::string> address;
            };
            struct pdbSymbol{
                std::string name;
                uint64_t address;
            
            };
            struct mappedFile
            {
                HANDLE file = nullptr;
                HANDLE mapping = nullptr;
                void* view = nullptr;
                std::size_t size = 0;

                ~mappedFile()
                {
                    if (view)    UnmapViewOfFile(view);
                    if (mapping) CloseHandle(mapping);
                    if (file)    CloseHandle(file);
                }
            };
            struct ddCodeview{
                uint32_t signature; 
                GUID guid;
                uint32_t age;
            };
            module(uint64_t ba, std::string mn, process& p);
            void readExportTableDirectory();
            void printModuleInformations();
            
            void readPdbSymbols(const std::wstring& pdbPath);
            void readDebugDirecotry();

            bool containsAddress(uint64_t address);
            
            std::vector<std::unique_ptr<vsdb::process::module::exportItem>> exports_; 
            std::vector<std::unique_ptr<vsdb::process::module::pdbSymbol>> pdbSymbols_; 
            std::string moduleName_;

        private:
        
            uint64_t baseAddress_;
            uint64_t moduleSize_;
            process& parent_;

            IMAGE_DOS_HEADER dosHeader_;
            IMAGE_NT_HEADERS64  peHeader_;

            uint16_t debugDirectoryDataLimit_ = 100;
        };

        class breakpointController{
            public: 
                struct breakpoint{
                    uint64_t address;
                    // std::vector<uint8_t> originalBytes;
                    uint16_t id;

                    bool operator<(const breakpoint& other) const {
                        if (address < other.address) return true;
                        if (address > other.address) return false;
                        return id < other.id;
                    }
                };
                breakpointController(process& p);

                void addBreakpoint(uint64_t address);
                void removeBreakpoint(uint16_t id);
                std::vector<vsdb::process::breakpointController::breakpoint> getListOfBreakpoints();

                void vsdb::process::breakpointController::setHardwareBreakpoints();


            private:
                process& parent_;

                std::vector<breakpoint> breakpoints_;
                uint16_t nextBreakpointId_ = 0;
                
                const int DR7_LEN_BITS[4] = {18, 22, 26, 30};
                const int DR7_RW_BITS[4]  = {16, 20, 24, 28};
                const int DR7_LE_BITS[4]  = {0, 2, 4, 6};

                const int DR7_LEN_SIZE = 2;
                const int DR7_RW_SIZE  = 2;
                
        };

        process(DWORD pid, bool isAttached): pid_(pid), isAttached_(isAttached), breakpointController_(*this){}
        DWORD pid_ = 0;
        process_state state_ = process_state::running;
        DEBUG_EVENT debugEvent_ = {};

        HANDLE hThread_ = nullptr;
        CONTEXT ctx_ = {};
        std::vector<std::unique_ptr<process::module>> modules_;
        breakpointController breakpointController_;

        bool isAttached_ = false;
        bool expectStep_ = false;

        std::vector<std::string> split(const std::string_view str, char delimiter);
        uint64_t stringToUint64(const std::string str);
        module* getContainingModule(uint64_t address);
        // std::string bytesToString(std::vector<uint8_t> bytes, bool isUnicode);

        
        std::vector<std::optional<uint8_t>> examinMemory(uint64_t address, size_t count);



        template <typename T>
        T bytesToData(uint64_t address);
        template <typename T>
        std::vector<T> bytesToArray(uint64_t address, size_t maxCount);
        std::string bytesToString(uint64_t address, size_t maxCount, bool isWide);

        template <typename T>
        void setBits(T& val, T set_val, std::size_t start_bit, std::size_t bit_count);


        std::string resolveAddressToSymbol(uint64_t address);
        uint64_t resolveSymbolToAddress(std::string symbolName);

        void displayData(std::vector<std::optional<uint8_t>> data, std::string type, uint64_t address=0, bool isWide=false);

        void handleOutputDebugStringEvent();
        void handleLoadDllDebugEvent();
        void handleCreateProcessDebugEvent();
        void handleExceptionDebugEvent();

        bool runAndWaitForDebugEvent();

        void commandPrint(std::vector<std::string> args);
        void commandContinue(std::vector<std::string> args);
        void commandStepInto(std::vector<std::string> args);
        void commandRun(std::vector<std::string> args);
        void commandQuit(std::vector<std::string> args);
        void commandResolveAddress(std::vector<std::string> args);
        void commandResolveSymbol(std::vector<std::string> args);
        void commandBreakpoint(std::vector<std::string> args);
        void commandBreakpointInfo(std::vector<std::string> args);
        void commandBreakpointRemove(std::vector<std::string> args);
        void commandHelp(std::string command);
    };
}
#endif

