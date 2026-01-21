#include <libvsdb/process.hpp>
#include <iostream>
#include <windows.h>
#include <replxx.hxx>
#include <cxxopts.hpp>

namespace{

    void debugerLoop(std::unique_ptr<vsdb::process>& process){
        replxx::Replxx rx;
        static std::string lastCommand = "";

        while(true){
            
            vsdb::process_state state = process->getState();
            if(state == vsdb::process_state::terminated || state == vsdb::process_state::exited){
                std::cout << "Process terminated or exited. Exiting debugger." << std::endl;
                break;
            }
            
            
            std::ostringstream  inputLine;
            
            if(state == vsdb::process_state::stopped || state == vsdb::process_state::running){
                inputLine << process->getBreakInfo();
            }
            inputLine << "> ";

            const char *line = rx.input(inputLine.str());
            if (line == nullptr) {
                return;
            }

            std::string command(line);
            if (command.empty()) {
                command = lastCommand;
            }

            lastCommand = command;
            rx.history_add(command.c_str());

            process->sendCommand(command);
        }
    }
}

int main(int argc, char** argv){

    cxxopts::Options options("vsdb", "A victors' simple debugger");
    options.add_options()
        ("p,pid", "Attach to process with given pid", cxxopts::value<DWORD>())
        ("e,exec", "Execute the given program", cxxopts::value<std::string>())
        ("h,help", "Print usage");

    cxxopts::ParseResult result;
    try{
        result = options.parse(argc, argv);    
    }catch(const std::exception& e){
        std::cerr << "Error parsing options: " << e.what() << "\n";
        std::cerr << options.help() << "\n";
        return 1;
    }
    if (result.count("help")) {
        std::cout << options.help() << "\n";
        return 0;
    }
    if (!result.count("pid") && !result.count("exec")) {
        std::cerr << "Error: exactly one of -p/--pid, -e/--exec is required\n";
        std::cerr << options.help() << "\n";
        return 1;
    }
    if (result.count("pid") && result.count("exec")) {
        std::cerr << "Error: only one of -p/--pid, -e/--exec is required\n";
        std::cerr << options.help() << "\n";
        return 1;
    }

    try{
        if (result.count("exec")) {
            std::string program = result["exec"].as<std::string>();
            auto process = vsdb::process::launch(program);
            debugerLoop(process);
        }else if (result.count("pid")) {
            DWORD pid = result["pid"].as<DWORD>();
            auto process = vsdb::process::attach(pid);
            debugerLoop(process);
        }
    }catch(const std::exception& e){
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
