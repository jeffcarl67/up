#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <elf.h>
#include <cstdio>
#include <unordered_map>
#include <memory>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <utility>
#include <capstone/capstone.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>

FILE *out = stdout;

class Command;
class Tracer;

class Command
{
public:
    explicit Command(Tracer *t): tracer{t} {};
    virtual void exec(std::vector<std::string>& argv) = 0;
protected:
    Tracer *tracer;
};

class Tracer
{
public:
    explicit Tracer(std::string script, std::string program);
    void cmdline(void);
    void load(std::vector<std::string>& argv);
    void start(std::vector<std::string>& argv);
    void vmmap(std::vector<std::string>& argv);
    void get(std::vector<std::string>& argv);
    void run(std::vector<std::string>& argv);
    void getregs(std::vector<std::string>& argv);
    void disasm(std::vector<std::string>& argv);
    void hw_break(std::vector<std::string>& argv);
    void list(std::vector<std::string>& argv);
    void cont(std::vector<std::string>& argv);
    void set(std::vector<std::string>& argv);
    void hw_delete(std::vector<std::string>& argv);
    void dump(std::vector<std::string>& argv);
    void si(std::vector<std::string>& argv);
    void quit(std::vector<std::string>& argv);
    void help(std::vector<std::string>& argv);
private:
    std::string script;
    std::string program;
    using Fcmd = void (Tracer::*)(std::vector<std::string>&);
    std::unordered_map<std::string, Fcmd> cmds;
    int state;
    std::string tracee;
    pid_t child;
    std::pair<Elf64_Addr, Elf64_Addr> text_range;
    std::vector<std::pair<bool, uint64_t>> bp_addrs;
    std::unordered_map<uint64_t, uint8_t> bp_addr_byte;
    std::pair<bool, long> last_stopped_rip;
};

enum State : int
{
    init = 0, loaded, running, end
};

void Tracer::load(std::vector<std::string>& argv)
{
    if (this->state != State::init) {
        fprintf(out, "** program already loaded\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** no program given\n");
        return;
    }
    if (argv.size() >= 2) {
        std::fstream f;
        Elf64_Ehdr head;
        Elf64_Shdr shdr;
        std::unique_ptr<char[]> shstr;
        f.open(argv[1], std::fstream::in | std::fstream::binary);
        if (!f) {
            fprintf(out, "** %s: %s\n", argv[1].c_str(), strerror(errno));
        }
        f.read((char*)&head, sizeof(head));
        f.seekg(head.e_shoff + head.e_shstrndx * head.e_shentsize, std::ios::beg);
        f.read((char*)&shdr, head.e_shentsize);
        if (shdr.sh_offset) {
            shstr = std::unique_ptr<char[]>{ new char[shdr.sh_size] };
            f.seekg(shdr.sh_offset, std::ios::beg);
            f.read(shstr.get(), shdr.sh_size);
        }
        f.seekg(head.e_shoff, std::ios::beg);
        for (int i = 0; i < head.e_shnum; i++) {
            f.read((char*)&shdr, head.e_shentsize);
            if (strcmp(shstr.get() + shdr.sh_name, ".text") == 0) {
                this->text_range = std::make_pair(shdr.sh_addr, shdr.sh_addr + shdr.sh_size);
                break;
            }
        }
        f.close();
        fprintf(out, "** program '%s' loaded. entry point 0x%lx\n", argv[1].c_str(), head.e_entry);
        this->state = State::loaded;
        this->tracee = argv[1];
        return;
    }
}

void Tracer::start(std::vector<std::string>& argv)
{
    if (this->state == State::init) {
        fprintf(out, "** program is not loaded\n");
        return;
    }
    if (this->state == State::running) {
        int status;
        kill(this->child, SIGKILL);
        
        if (waitpid(this->child, &status, 0) < 0) {
            fprintf(out, "** waitpid: %s\n", strerror(errno));
            return;
        }
        
        if (WIFSIGNALED(status)) {
            this->state = State::loaded;
            this->bp_addrs.clear();
            this->bp_addr_byte.clear();
            std::vector<std::string> cmd = {"start"};
            this->start(cmd);
        }
        
        return;
    }
    if (argv.size() >= 1) {
        pid_t child;
        child = fork();
        if (child < 0) {
            fprintf(out, "** fork: %s\n", strerror(errno));
            return;
        }
        else if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
                fprintf(out, "** PTRACE_TRACEME: %s\n", strerror(errno));
                exit(1);
            }
            if (execlp(this->tracee.c_str(), this->tracee.c_str(), NULL) < 0) {
                fprintf(out, "** exec: %s\n", strerror(errno));
                exit(1);
            }
        }
        else {
            int status;
            this->child = child;
            fprintf(out, "** pid %d\n", child);
            if (waitpid(child, &status, 0) < 0) {
                fprintf(out, "** waitpid: %s\n", strerror(errno));
                return;
            }
            if (WIFEXITED(status)) {

            }
            if (WIFSTOPPED(status)) {
                if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0) {
                    fprintf(out, "** PTRACE_SETOPTIONS: %s\n", strerror(errno));
                    return;
                }
            }
            this->state = State::running;
        }
    }
}

void Tracer::vmmap(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() >= 1) {
        std::stringstream ss;
        std::string pid;
        std::fstream f;
        std::vector<std::string> maps;
        ss << this->child;
        ss >> pid;
        f.open("/proc/" + pid + "/maps", std::fstream::in);
        if (!f) {
            fprintf(out, "** /proc/%s/maps: %s\n", pid.c_str(), strerror(errno));
            return;
        }
        while (true) {
            std::string line;
            std::string token;
            size_t pos = 0;

            long start;
            long end;
            std::string rwx;
            long offset;
            std::string device;
            long inode;
            std::string pathname;
            
            std::getline(f, line);
            if (f.eof()) break;
            if ((pos = line.find("-")) != std::string::npos) {
                token = line.substr(0, pos);
                start = strtol(token.c_str(), NULL, 16);
                line.erase(0, pos + 1);
            }
            if ((pos = line.find(" ")) != std::string::npos) {
                token = line.substr(0, pos);
                end = strtol(token.c_str(), NULL, 16);
                line.erase(0, pos + 1);
            }
            if ((pos = line.find(" ")) != std::string::npos) {
                token = line.substr(0, pos);
                if (! token.empty())
                    token.pop_back();
                rwx = token;
                line.erase(0, pos + 1);
            }
            if ((pos = line.find(" ")) != std::string::npos) {
                token = line.substr(0, pos);
                offset = strtol(token.c_str(), NULL, 16);
                line.erase(0, pos + 1);
            }
            if ((pos = line.find(" ")) != std::string::npos) {
                token = line.substr(0, pos);
                device = token;
                line.erase(0, pos + 1);
            }
            if ((pos = line.find(" ")) != std::string::npos) {
                token = line.substr(0, pos);
                inode = strtol(token.c_str(), NULL, 10);
                line.erase(0, pos + 1);
            }
            std::stringstream ss(line);
            ss >> pathname;

            fprintf(out, "%016lx-%016lx %s %20ld\t", start, end, rwx.c_str(), inode);
            fprintf(out, "%s\n", pathname.c_str());            
        }
    }
}

static struct user_regs_struct regs;
static std::unordered_map<std::string, ptrdiff_t> regs_offset = {
    {"rax", (char*)&regs.rax - (char*)&regs},
    {"rbx", (char*)&regs.rbx - (char*)&regs},
    {"rcx", (char*)&regs.rcx - (char*)&regs},
    {"rdx", (char*)&regs.rdx - (char*)&regs},
    {"r8", (char*)&regs.r8 - (char*)&regs},
    {"r9", (char*)&regs.r9 - (char*)&regs},
    {"r10", (char*)&regs.r10 - (char*)&regs},
    {"r11", (char*)&regs.r11 - (char*)&regs},
    {"r12", (char*)&regs.r12 - (char*)&regs},
    {"r13", (char*)&regs.r13 - (char*)&regs},
    {"r14", (char*)&regs.r14 - (char*)&regs},
    {"r15", (char*)&regs.r15 - (char*)&regs},
    {"rdi", (char*)&regs.rdi - (char*)&regs},
    {"rsi", (char*)&regs.rsi - (char*)&regs},
    {"rbp", (char*)&regs.rbp - (char*)&regs},
    {"rsp", (char*)&regs.rsp - (char*)&regs},
    {"rip", (char*)&regs.rip - (char*)&regs},
    {"eflags", (char*)&regs.eflags - (char*)&regs},
    {"flags", (char*)&regs.eflags - (char*)&regs}
};

void Tracer::get(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** no reg is given.\n");
        return;
    }
    if (argv.size() >= 2) {
        if (regs_offset.find(argv[1]) != regs_offset.end()) {
            long reg;
            errno = 0;
            reg = ptrace(PTRACE_PEEKUSER, this->child, regs_offset[argv[1]], 0);
            if (errno != 0) {
                fprintf(out, "** PTRACE_PEEKUSER: %s\n", strerror(errno));
                return;
            }
            fprintf(out, "%s = %ld (0x%lx)\n", argv[1].c_str(), reg, reg);
        }
        return;
    }
}

void Tracer::run(std::vector<std::string>& argv)
{
    if (this->state == State::init) {
        fprintf(out, "** program is not loaded\n");
        return;
    }
    if (this->state == State::loaded) {
        pid_t child;
        child = fork();
        if (child < 0) {
            fprintf(out, "** fork: %s\n", strerror(errno));
            return;
        }
        else if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
                fprintf(out, "** PTRACE_TRACEME: %s\n", strerror(errno));
                exit(1);
            }
            if (execlp(this->tracee.c_str(), this->tracee.c_str(), NULL) < 0) {
                fprintf(out, "** exec: %s\n", strerror(errno));
                exit(1);
            }
        }
        else {
            int status;
            this->child = child;
            fprintf(out, "** pid %d\n", child);
            if (waitpid(child, &status, 0) < 0) {
                fprintf(out, "** waitpid: %s\n", strerror(errno));
                return;
            }
            if (WIFEXITED(status)) {

            }
            if (WIFSTOPPED(status)) {
                this->state = State::running;
                if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0) {
                    fprintf(out, "** PTRACE_SETOPTIONS: %s\n", strerror(errno));
                    return;
                }
                if (ptrace(PTRACE_CONT, child, 0, 0) < 0) {
                    fprintf(out, "** PTRACE_CONT: %s\n", strerror(errno));
                    return;
                }
                if (waitpid(child, &status, 0) < 0) {
                    fprintf(out, "** waitpid: %s\n", strerror(errno));
                    return;
                }
                if (WIFEXITED(status)) {
                    int code = WEXITSTATUS(status);
                    if (code == 0)
                        fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
                    else
                        fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
                    this->state = State::loaded;
                    this->bp_addrs.clear();
                    this->bp_addr_byte.clear();
                    this->last_stopped_rip.first = false;
                }
                if (WIFSTOPPED(status)) {

                }
            }
        }
    }
    if (this->state == State::running) {
        int status;
        fprintf(out, "** program %s is already running.\n", this->tracee.c_str());
        std::vector<std::string> cmd = {"cont"};
        this->cont(cmd);
    }
}

void Tracer::getregs(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() >= 1) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, this->child, 0, &regs) < 0) {
            fprintf(out, "** PTRACE_GETREGS: %s\n", strerror(errno));
            return;
        }
        fprintf(out, "RAX %-16llx RBX %-16llx RCX %-16llx RDX %-16llx\n"
                        "R8  %-16llx R9  %-16llx R10 %-16llx R11 %-16llx\n"
                        "R12 %-16llx R13 %-16llx R14 %-16llx R15 %-16llx\n"
                        "RDI %-16llx RSI %-16llx RBP %-16llx RSP %-16llx\n"
                        "RIP %-16llx FLAGS %016llx\n",
                        regs.rax, regs.rbx, regs.rcx, regs.rdx,
                        regs.r8, regs.r9, regs.r10, regs.r11,
                        regs.r12, regs.r13, regs.r14, regs.r15,
                        regs.rdi, regs.rsi, regs.rbp, regs.rsp,
                        regs.rip, regs.eflags);
    }
}

void Tracer::disasm(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** no addr is given.\n");
        return;
    }
    if (argv.size() >= 2) {
        uint64_t addr = 0;
        uint8_t code[160] = {0};
        int code_size;
        long peek;
        csh handle;
        cs_insn *insn;
        size_t count;
        addr = strtol(argv[1].c_str(), NULL, 0);
        if (addr < this->text_range.first or addr >= this->text_range.second)
            return;
        code_size = this->text_range.second - addr < 160 ?
                    this->text_range.second - addr : 160;
        int aligned_code_size = (code_size + 7) & (~ 0x7);
        for (int i = 0; i < aligned_code_size; i += 8) {
            errno = 0;
            peek = ptrace(PTRACE_PEEKTEXT, this->child, addr + i, 0);
            if (errno != 0) {
                code_size = i;
                break;
            }
            memcpy(code + i, &peek, 8);
        }
        for (int i = 0; i < code_size; i++) {
            if (this->bp_addr_byte.find(addr + i) != this->bp_addr_byte.end())
                code[i] = this->bp_addr_byte[addr + i];
        }
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            return;
        }
        count = cs_disasm(handle, code, code_size, addr, 10, &insn);
        if (count > 0) {
            for (int i = 0; i < count; i++) {
                fprintf(out, "      %lx: ", insn[i].address);
                for (int j = 0; j < 15; j++) {
                    if (j < insn[i].size)
                        fprintf(out, "%02x ", (unsigned char) insn[i].bytes[j]);
                    else
                        fprintf(out, "   ");
                }
                fprintf(out, "\t\t");
                fprintf(out, "%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
            }
            cs_free(insn, count);
        }
        cs_close(&handle);
        return;
    }
}

void Tracer::hw_break(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** no addr is given");
        return;
    }
    if (argv.size() >= 2) {
        std::stringstream ss;
        uint64_t addr;
        long code;
        uint8_t byte;

        ss << std::hex << argv[1];
        ss >> addr;

        errno = 0;
        code = ptrace(PTRACE_PEEKTEXT, this->child, addr, 0);
        if (errno != 0) return;

        byte = ((uint8_t *)&code)[0];
        ((uint8_t *)&code)[0] = 0xcc;

        if (ptrace(PTRACE_POKETEXT, this->child, addr, code) < 0) {
            fprintf(out, "** PTRACE_POKETEXT: %s\n", strerror(errno));
            return;
        }
        this->bp_addrs.push_back({true, addr});
        this->bp_addr_byte[addr] = byte;
        return;
    }
}

void Tracer::list(std::vector<std::string>& argv)
{
    for (int i = 0; i < this->bp_addrs.size(); i++) {
        if (this->bp_addrs[i].first)
            fprintf(out, "  %d: %lx\n", i, this->bp_addrs[i].second);
    }
}

void Tracer::cont(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() >= 1) {
        int status;
        long rip;

        errno = 0;
        rip = ptrace(PTRACE_PEEKUSER, this->child, regs_offset["rip"], 0);
        if (errno != 0) return;

        if (this->last_stopped_rip.first and this->last_stopped_rip.second == rip) {
            long code;
            if (this->bp_addr_byte.find(rip) != this->bp_addr_byte.end()) {
                errno = 0;
                code = ptrace(PTRACE_PEEKTEXT, this->child, rip, 0);
                if (errno != 0) return;
                ((uint8_t *)&code)[0] = this->bp_addr_byte[rip];
                if (ptrace(PTRACE_POKETEXT, this->child, rip, code) < 0) {
                    fprintf(out, "** PTRACE_POKETEXT: %s\n", strerror(errno));
                    return;
                }
            }
        }

        if (ptrace(PTRACE_SINGLESTEP, this->child, 0, 0) < 0) {
            fprintf(out, "** PTRACE_SINGLESTEP: %s\n", strerror(errno));
            return;
        }
        if (waitpid(this->child, &status, 0) < 0) {
            fprintf(out, "** waitpid: %s\n", strerror(errno));
            return;
        }
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 0)
                fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
            else
                fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
            this->state = State::loaded;
            this->bp_addrs.clear();
            this->bp_addr_byte.clear();
            this->last_stopped_rip.first = false;
        }
        if (WIFSTOPPED(status)) {
            long code[2] = {0};
            int code_size = 16;
            uint8_t byte;
            csh handle;
            cs_insn *insn;
            size_t count;
            
            errno = 0;
            code[0] = ptrace(PTRACE_PEEKTEXT, this->child, rip, 0);
            if (errno != 0) return;

            
            if (this->bp_addr_byte.find(rip) != this->bp_addr_byte.end()) {
                byte = ((uint8_t *)&code)[0];
                if (byte == 0xcc) { // breakpoint
                    ((uint8_t *)code)[0] = this->bp_addr_byte[rip];
                    errno = 0;
                    code[1] = ptrace(PTRACE_PEEKTEXT, this->child, rip + 8, 0);
                    if (errno != 0) code_size = 8;
                    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                        return;
                    }
                    count = cs_disasm(handle, (uint8_t*)code, code_size, rip, 1, &insn);
                    if (count > 0) {
                        fprintf(out, "** breakpoint @\t%lx: ", insn[0].address);
                        for (int i = 0; i < 15; i++) {
                            if (i < insn[0].size)
                                fprintf(out, "%02x ", (unsigned char) insn[0].bytes[i]);
                            else
                                fprintf(out, "   ");
                        }
                        fprintf(out, "%s\t%s\n", insn[0].mnemonic, insn[0].op_str);
                        cs_free(insn, count);
                    }
                    cs_close(&handle);
                    if (ptrace(PTRACE_POKEUSER, this->child, regs_offset["rip"], rip) < 0) {
                        fprintf(out, "** PTRACE_POKEUSER: %s\n", strerror(errno));
                        return;
                    }
                    this->last_stopped_rip.first = true;
                    this->last_stopped_rip.second = rip;
                    return;
                }
                else { // instruction finished
                    ((uint8_t *)code)[0] = 0xcc;
                    if (ptrace(PTRACE_POKETEXT, this->child, rip, code[0]) < 0) {
                        fprintf(out, "** PTRACE_POKETEXT: %s\n", strerror(errno));
                        return;
                    }
                }
            }
        }

        if (ptrace(PTRACE_CONT, this->child, 0, 0) < 0) {
            fprintf(out, "** PTRACE_CONT: %s\n", strerror(errno));
            return;
        }
        if (waitpid(this->child, &status, 0) < 0) {
            fprintf(out, "** waitpid: %s\n", strerror(errno));
            return;
        }
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 0)
                fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
            else
                fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
            this->state = State::loaded;
            this->bp_addrs.clear();
            this->bp_addr_byte.clear();
            this->last_stopped_rip.first = false;
        }
        if (WIFSTOPPED(status)) {
            long rip;
            uint8_t code[16] = {0};
            long peek;
            csh handle;
            cs_insn *insn;
            size_t count;
            int code_size = 16;

            errno = 0;
            rip = ptrace(PTRACE_PEEKUSER, this->child, regs_offset["rip"], 0);
            if (errno != 0) return;

            rip = rip - 1;
            if (this->bp_addr_byte.find(rip) == this->bp_addr_byte.end())
                return;
            for (int i = 0; i < 16; i += 8) {
                errno = 0;
                peek = ptrace(PTRACE_PEEKTEXT, this->child, rip + i, 0);
                if (errno != 0) {
                    code_size = i;
                    break;
                }
                memcpy(code + i, &peek, 8);
            }
            code[0] = this->bp_addr_byte[rip];
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                return;
            }
            count = cs_disasm(handle, code, code_size, rip, 1, &insn);
            if (count > 0) {
                fprintf(out, "** breakpoint @\t%lx: ", insn[0].address);
                for (int i = 0; i < 15; i++) {
                    if (i < insn[0].size)
                        fprintf(out, "%02x ", (unsigned char) insn[0].bytes[i]);
                    else
                        fprintf(out, "   ");
                }
                fprintf(out, "%s\t%s\n", insn[0].mnemonic, insn[0].op_str);
                cs_free(insn, count);
            }
            cs_close(&handle);
            
            if (ptrace(PTRACE_POKEUSER, this->child, regs_offset["rip"], rip) < 0) {
                fprintf(out, "** PTRACE_POKEUSER: %s", strerror(errno));
                return;
            }
            this->last_stopped_rip.first = true;
            this->last_stopped_rip.second = rip;
        }
        return;
    }
}

void Tracer::set(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** reg and value are not given");
        return;
    }
    if (argv.size() == 2) {
        fprintf(out, "** value is not given");
        return;
    }
    if (argv.size() >= 3) {
        long value = 0;

        value = strtol(argv[2].c_str(), NULL, 0);

        if (regs_offset.find(argv[1]) == regs_offset.end()) {
            return;
        }
        if (ptrace(PTRACE_POKEUSER, this->child, regs_offset[argv[1]], value) < 0) {
            fprintf(out, "** PTRACE_POKEUSER: %s\n", strerror(errno));
            return;
        }
    }
}

void Tracer::hw_delete(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** no number is given");
        return;
    }
    if (argv.size() >= 2) {
        long num = -1;
        uint64_t addr;
        long code;

        num = strtol(argv[1].c_str(), NULL, 0);

        if (num >= 0 and num < this->bp_addrs.size()) {
            if (this->bp_addrs[num].first == true) {
                this->bp_addrs[num].first = false;
                addr = this->bp_addrs[num].second;
                
                errno = 0;
                code = ptrace(PTRACE_PEEKTEXT, this->child, addr, 0);
                if (errno != 0) return;

                ((uint8_t *)&code)[0] = this->bp_addr_byte[addr];
                if (ptrace(PTRACE_POKETEXT, this->child, addr, code) < 0) {
                    fprintf(out, "** PTRACE_POKETEXT: %s\n", strerror(errno));
                    return;
                }

                auto n = this->bp_addr_byte.erase(addr);
                fprintf(out, "** breakpoint %ld deleted.\n", num);
            }
        }
    }
}

void Tracer::dump(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() == 1) {
        fprintf(out, "** no addr is given\n");
        return;
    }
    if (argv.size() >= 2) {
        long addr;
        long code;
        char buf[80] = {0};
        int buf_size = 80;

        addr = strtol(argv[1].c_str(), NULL, 0);
        for (int i = 0; i < 80; i += 8) {
            errno = 0;
            code = ptrace(PTRACE_PEEKTEXT, this->child, addr + i, 0);
            if (errno != 0) {
                buf_size = i;
                break;
            }
            memcpy(buf + i, &code, 8);
        }
        for (int i = 0; i < buf_size; i += 16) {
            fprintf(out, "      %lx: ", addr + i);
            for (int j = 0; j < 16; j++) {
                if (i + j < buf_size) {
                    fprintf(out, "%02x ", (unsigned char) buf[i + j]);
                }
                else {
                    fprintf(out, "   ");
                }
            }
            fprintf(out, " |");
            for (int j = 0; j < 16; j++) {
                if (i + j < buf_size) {
                    if (isprint(buf[i + j]))
                        fprintf(out, "%c", buf[i + j]);
                    else
                        fprintf(out, ".");
                }
                else {
                    fprintf(out, " ");
                }
            }
            fprintf(out, "|\n");
        }
        return;
    }
}

void Tracer::si(std::vector<std::string>& argv)
{
    if (this->state != State::running) {
        fprintf(out, "** program is not running\n");
        return;
    }
    if (argv.size() >= 1) {
        int status;
        long rip;

        errno = 0;
        rip = ptrace(PTRACE_PEEKUSER, this->child, regs_offset["rip"], 0);
        if (errno != 0) return;

        if (this->last_stopped_rip.first and this->last_stopped_rip.second == rip) {
            long code;
            if (this->bp_addr_byte.find(rip) != this->bp_addr_byte.end()) {
                errno = 0;
                code = ptrace(PTRACE_PEEKTEXT, this->child, rip, 0);
                if (errno != 0) return;
                ((uint8_t *)&code)[0] = this->bp_addr_byte[rip];
                if (ptrace(PTRACE_POKETEXT, this->child, rip, code) < 0) {
                    fprintf(out, "** PTRACE_POKETEXT: %s\n", strerror(errno));
                    return;
                }
            }
        }

        if (ptrace(PTRACE_SINGLESTEP, this->child, 0, 0) < 0) {
            fprintf(out, "** PTRACE_SINGLESTEP: %s\n", strerror(errno));
            return;
        }
        if (waitpid(this->child, &status, 0) < 0) {
            fprintf(out, "** waitpid: %s\n", strerror(errno));
            return;
        }
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 0)
                fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
            else
                fprintf(out, "** child process %d terminated normally (code %d)\n", child, code);
            this->state = State::loaded;
            this->bp_addrs.clear();
            this->bp_addr_byte.clear();
            this->last_stopped_rip.first = false;
        }
        if (WIFSTOPPED(status)) {
            long code[2] = {0};
            int code_size = 16;
            uint8_t byte;
            csh handle;
            cs_insn *insn;
            size_t count;
            
            errno = 0;
            code[0] = ptrace(PTRACE_PEEKTEXT, this->child, rip, 0);
            if (errno != 0) return;

            
            if (this->bp_addr_byte.find(rip) != this->bp_addr_byte.end()) {
                byte = ((uint8_t *)&code)[0];
                if (byte == 0xcc) { // breakpoint
                    ((uint8_t *)code)[0] = this->bp_addr_byte[rip];
                    errno = 0;
                    code[1] = ptrace(PTRACE_PEEKTEXT, this->child, rip + 8, 0);
                    if (errno != 0) code_size = 8;
                    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                        return;
                    }
                    count = cs_disasm(handle, (uint8_t*)code, code_size, rip, 1, &insn);
                    if (count > 0) {
                        fprintf(out, "** breakpoint @\t%lx: ", insn[0].address);
                        for (int i = 0; i < 15; i++) {
                            if (i < insn[0].size)
                                fprintf(out, "%02x ", (unsigned char) insn[0].bytes[i]);
                            else
                                fprintf(out, "   ");
                        }
                        fprintf(out, "%s\t%s\n", insn[0].mnemonic, insn[0].op_str);
                        cs_free(insn, count);
                    }
                    cs_close(&handle);
                    if (ptrace(PTRACE_POKEUSER, this->child, regs_offset["rip"], rip) < 0) {
                        fprintf(out, "** PTRACE_POKEUSER: %s\n", strerror(errno));
                        return;
                    }
                    this->last_stopped_rip.first = true;
                    this->last_stopped_rip.second = rip;
                    return;
                }
                else { // instruction finished
                    ((uint8_t *)code)[0] = 0xcc;
                    if (ptrace(PTRACE_POKETEXT, this->child, rip, code[0]) < 0) {
                        fprintf(out, "** PTRACE_POKETEXT: %s\n", strerror(errno));
                        return;
                    }
                }
            }
        }
        return;
    }
}

void Tracer::quit(std::vector<std::string>& argv)
{
    this->state = State::end;
}

void Tracer::help(std::vector<std::string>& argv)
{
    char msg[] = "- break {instruction-address}: add a break point\n"
                 "- cont: continue execution\n"
                 "- delete {break-point-id}: remove a break point\n"
                 "- disasm addr: disassemble instructions in a file or a memory region\n"
                 "- dump addr [length]: dump memory content\n"
                 "- exit: terminate the debugger\n"
                 "- get reg: get a single value from a register\n"
                 "- getregs: show registers\n"
                 "- help: show this message\n"
                 "- list: list break points\n"
                 "- load {path/to/a/program}: load a program\n"
                 "- run: run the program\n"
                 "- vmmap: show memory layout\n"
                 "- set reg val: get a single value to a register\n"
                 "- si: step into instruction\n"
                 "- start: start the program and stop at the first instruction\n";
    fprintf(out, "%s", msg);
}

Tracer::Tracer(std::string script, std::string program)
: script(script), program(program),
cmds{}, state{State::init}, tracee{}, text_range{},
bp_addrs{}, bp_addr_byte{}, last_stopped_rip{false, 0}
{
    //auto load = std::make_shared<Load>(this);
    cmds["load"] = &Tracer::load;
    cmds["start"] = &Tracer::start;
    cmds["vmmap"] = &Tracer::vmmap;
    cmds["m"] = &Tracer::vmmap;
    cmds["get"] = &Tracer::get;
    cmds["g"] = &Tracer::get;
    cmds["run"] = &Tracer::run;
    cmds["r"] = &Tracer::run;
    cmds["getregs"] = &Tracer::getregs;
    cmds["disasm"] = &Tracer::disasm;
    cmds["d"] = &Tracer::disasm;
    cmds["break"] = &Tracer::hw_break;
    cmds["b"] = &Tracer::hw_break;
    cmds["list"] = &Tracer::list;
    cmds["l"] = &Tracer::list;
    cmds["cont"] = &Tracer::cont;
    cmds["c"] = &Tracer::cont;
    cmds["set"] = &Tracer::set;
    cmds["s"] = &Tracer::set;
    cmds["delete"] = &Tracer::hw_delete;
    cmds["dump"] = &Tracer::dump;
    cmds["x"] = &Tracer::dump;
    cmds["si"] = &Tracer::si;
    cmds["quit"] = &Tracer::quit;
    cmds["q"] = &Tracer::quit;
    cmds["help"] = &Tracer::help;
    cmds["h"] = &Tracer::help;

    if (! program.empty()) {
        std::vector<std::string> cmd = {"load", program};
        this->load(cmd);
    }
}

void
Tracer::cmdline(void)
{
    std::string cmd;
    std::fstream sf;
    std::istream *f = &std::cin;
    if (! this->script.empty()) {
        sf.open(this->script, std::fstream::in);
        if (sf)
            f = &sf;
    }
    while (this->state != State::end) {
        if (f->eof()) break;
        if (script.empty())
            std::cout << "sdb> ";
        std::getline(*f, cmd);
        std::vector<std::string> argv;
        std::stringstream ss(cmd);
        std::string s;
        while (ss >> s) {
            argv.push_back(s);
        }
        if (argv.empty()) continue;
        if (this->cmds.find(argv[0]) != this->cmds.end()) {
            (this->*(this->cmds[argv[0]]))(argv);
        } else {
            fprintf(out, "** no such command: %s\n", argv[0].c_str());
        }
    }
    if (sf)
        sf.close();
    fprintf(out, "Bye.\n");
}


int
main(int argc, char** argv)
{
    int opt;
    std::string script;
    std::string program;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    while ((opt = getopt(argc, argv, "s:")) != -1) {
        if (opt == 's')
            script = optarg;
    }
    if (optind < argc)
        program = argv[optind];
    Tracer a{script, program};
    a.cmdline();
}