#include <sys/types.h>
#include <dirent.h>
#include <vector>
#include <cassert>
#include <iostream>
#include <string>
#include <regex>
#include <fstream>
#include <sstream>
#include <pwd.h>
#include <unistd.h>
#include <algorithm>
#include <utility>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

const std::string readlink_denied = " (readlink: Permission denied)";
const std::string opendir_denied = " (opendir: Permission denied)";
const std::string deleted = " (deleted)";

class open_file;
class process;
std::ostream& operator<< (std::ostream&, const open_file&);
std::ostream& operator<< (std::ostream&, const process&);

std::string get_type(mode_t);

class filter;

class open_file
{
public:
    open_file(std::string command, pid_t pid, std::string user,
    std::string fd, std::string type, ino_t node, std::string name)
    : command(command), pid(pid), user(user), fd(fd), type(type),
    node(node), name(name) {}
private:
    std::string command;
    pid_t pid;
    std::string user;
    std::string fd;
    std::string type;
    ino_t node;
    std::string name;
    friend std::ostream& operator<< (std::ostream&, const open_file&);
    friend class filter;
};

std::ostream&
operator<< (std::ostream& os, const open_file& of)
{
    os << of.command << " " << of.pid << " " << of.user
    << " " << of.fd << " " << of.type << " ";
    if (not of.node)
        os << " ";
    else
        os << of.node;
    os << " " << of.name;
    return os;
}

class process
{
public:
    explicit process(const std::string& path, pid_t pid)
    : path(path), pid(pid) {}
    static std::vector<process> get_processes(void);
    std::vector<open_file> lsof(void);
    bool operator< (const process&);

private:
    void read_command(const std::string&);
    void read_username(const std::string&);
    std::pair<bool, bool> read_cwd(const std::string&);
    std::pair<bool, bool> read_root(const std::string&);
    std::pair<bool, bool> read_exe(const std::string&);
    std::pair<bool, bool> read_mem(const std::string&);
    std::pair<bool, bool> read_fd(const std::string&);
    open_file of_cwd(std::pair<bool, bool>);
    open_file of_root(std::pair<bool, bool>);
    open_file of_exe(std::pair<bool, bool>);
    std::vector<open_file> of_mem(std::pair<bool, bool>);
    std::vector<open_file> of_fd(std::pair<bool, bool>);
    open_file create_of(std::string, std::string, ino_t, std::string);

    friend std::ostream& operator<< (std::ostream&, const process&);
    
    std::string path;
    pid_t pid;
    std::string command;
    std::string username;
    std::string cwd;
    std::string root;
    std::string exe;
    std::vector<std::pair<ino_t, std::string>> mem;
    std::vector<int> fd;
    std::vector<open_file> of;
};

std::ostream&
operator<< (std::ostream& os, const process& p)
{
    for (const auto f: p.of)
        os << f << "\n";
    return os;
}

bool
process::operator<(const process& p)
{
    return this->pid < p.pid;
}

std::vector<process>
process::get_processes(void)
{
    std::regex pid_regex("[1-9][0-9]*");
    DIR *proc = opendir("/proc");
    struct dirent *direntp;
    pid_t pid;
    std::vector<process> processes;
    assert(proc);
    while ((direntp = readdir(proc))) {
        std::string d_name(direntp->d_name);
        std::stringstream ss(d_name);
        ss >> pid;
        if (std::regex_match(d_name, pid_regex))
            processes.push_back(process("/proc/" + d_name, pid));
    }
    closedir(proc);
    return processes;
}

std::vector<open_file>
process::lsof(void)
{
    read_command(path + "/comm");
    read_username(path + "/status");
    std::pair<bool, bool> b_cwd = read_cwd(path + "/cwd");
    std::pair<bool, bool> b_root = read_root(path + "/root");
    std::pair<bool, bool> b_exe = read_exe(path + "/exe");
    std::pair<bool, bool> b_mem = read_mem(path + "/maps");
    std::pair<bool, bool> b_fd = read_fd(path + "/fd");
    this->of.push_back(of_cwd(b_cwd));
    this->of.push_back(of_root(b_root));
    this->of.push_back(of_exe(b_exe));
    std::vector<open_file> f = of_mem(b_mem);
    this->of.insert(of.end(), f.begin(), f.end());
    std::vector<open_file> f2 = of_fd(b_fd);
    this->of.insert(of.end(), f2.begin(), f2.end());
    return this->of;
}

void
process::read_command(const std::string& path)
{
    std::ifstream f;
    f.open(path);
    if (f) {
        std::getline(f, this->command);
        f.close();
    }
}

void
process::read_username(const std::string& path)
{
    std::ifstream f;
    std::string line;
    uid_t uid;
    struct passwd *pw;
    f.open(path);
    if (f) {
        while (std::getline(f, line) and line.rfind("Uid", 0) != 0);
        std::stringstream ss(line);
        std::string a; // store "Uid:"
        ss >> a >> uid;
        pw = getpwuid(uid);
        this->username = pw->pw_name;
        f.close();
    }
}

static char buf[1024];

std::pair<bool, bool>
process::read_cwd(const std::string& path)
{
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf)-1);
    if (len != -1) {
        buf[len] = 0;
        this->cwd = buf;
        return std::pair<bool, bool>(true, false);
    } else {
        if (errno == EACCES)
            return std::pair<bool, bool>(false, true);
        else
            return std::pair<bool, bool>(false, false);
    }
}

std::pair<bool, bool>
process::read_root(const std::string& path)
{
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf)-1);
    if (len != -1) {
        buf[len] = 0;
        this->root = buf;
        return std::pair<bool, bool>(true, false);
    } else {
        if (errno == EACCES)
            return std::pair<bool, bool>(false, true);
        else
            return std::pair<bool, bool>(false, false);
    }
}

std::pair<bool, bool>
process::read_exe(const std::string& path)
{
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf)-1);
    if (len != -1) {
        buf[len] = 0;
        this->exe = buf;
        return std::pair<bool, bool>(true, false);
    } else {
        if (errno == EACCES)
            return std::pair<bool, bool>(false, true);
        else
            return std::pair<bool, bool>(false, false);

    }
}

std::pair<bool, bool>
process::read_mem(const std::string& path)
{
    std::ifstream f;
    std::string line;
    std::string fpath;
    std::string placeholder;
    ino_t inode;
    f.open(path);
    if (f) {
        while (std::getline(f, line)) {
            std::stringstream ss(line);
            ss >> placeholder >> placeholder >> placeholder >> placeholder;
            ss >> inode;
            if (inode) std::getline(ss, fpath);
            fpath.erase(0, fpath.find_first_not_of(" ")); // remove leading space
            std::pair<ino_t, std::string> p(inode, fpath);
            if (inode and 
            std::find(this->mem.begin(), this->mem.end(), p) == this->mem.end())
                this->mem.push_back(p);
        }
        f.close();
        return std::pair<bool, bool>(true, false);
    }
    else {
        if (errno == EACCES)
            return std::pair<bool, bool>(false, true);
        else
            return std::pair<bool, bool>(false, false);
    }
}

std::pair<bool, bool>
process::read_fd(const std::string& path)
{
    std::regex fd_regex("[0-9]+");
    DIR *fdD = opendir(path.c_str());
    struct dirent *direntp;
    int fd;
    if (fdD) {
        while ((direntp = readdir(fdD))) {
            std::string d_name(direntp->d_name);
            std::stringstream ss(d_name);
            ss >> fd;
            if (std::regex_match(d_name, fd_regex))
                this->fd.push_back(fd);
        }
        closedir(fdD);
        return std::pair<bool, bool>(true, false);
    }
    else {
        if (errno == EACCES)
            return std::pair<bool, bool>(false, true);
        else
            return std::pair<bool, bool>(false, false);
    }
}

std::string
get_type(mode_t m)
{
    if (S_ISDIR(m))
        return "DIR";
    else if (S_ISREG(m))
        return "REG";
    else if (S_ISCHR(m))
        return "CHR";
    else if (S_ISFIFO(m))
        return "FIFO";
    else if (S_ISSOCK(m))
        return "SOCK";
    else
        return "unknown";
}

std::pair<ino_t, std::string>
get_stat(const std::string& path)
{
    struct stat st;
    int r = stat(path.c_str(), &st);
    if (r == 0)
        return std::pair<ino_t, std::string>(st.st_ino, get_type(st.st_mode));
    else
        return std::pair<ino_t, std::string>(0, "unknown");
}

std::string
get_fmode(const std::string& path)
{
    struct stat st;
    int r = lstat(path.c_str(), &st);
    if (r == 0) {
        if ((st.st_mode & S_IRUSR) and (st.st_mode & S_IWUSR))
            return "u";
        else if (st.st_mode & S_IRUSR)
            return "r";
        else if (st.st_mode & S_IWUSR)
            return "w";
        else
            return "";
    }
    else
        return "";
}

std::string
get_fdinfo(const std::string& path)
{
    std::ifstream f;
    std::string mode;
    std::stringstream ss;
    int flag = 0;
    f.open(path);
    if (f) {
        f >> mode >> mode >> mode >> mode;
        ss << std::oct << mode;
        ss >> flag;
        f.close();
        if ((flag & O_RDWR) or (O_RDWR == 0 and (flag & 1) == 0))
            return "u";
        else if ((flag & O_WRONLY) or (O_WRONLY == 0 and (flag & 1) == 0))
            return "w";
        else if ((flag & O_RDONLY) or (O_RDONLY == 0 and (flag & 1) == 0))
            return "r";
        else
            return "";
    }
    else
        return "";
}

open_file
process::create_of(std::string fd, std::string type, ino_t node, std::string name)
{
    return open_file(this->command, this->pid, this->username,
    fd, type, node, name);
}

open_file
process::of_cwd(std::pair<bool, bool> granted)
{
    if (not granted.first and granted.second)
        return create_of("cwd", "unknown", 0, this->path + "/cwd" + readlink_denied);
    else if (not granted.first)
        return create_of("cwd", "unknown", 0, this->path + "/cwd");
    std::pair<ino_t, std::string> p = get_stat(this->cwd);
    return create_of("cwd", p.second, p.first, this->cwd);
}

open_file
process::of_root(std::pair<bool, bool> granted)
{
    if (not granted.first and granted.second)
        return create_of("root", "unknown", 0, this->path + "/root" + readlink_denied);
    else if (not granted.first)
        return create_of("root", "unknown", 0, this->path + "/root");
    std::pair<ino_t, std::string> p = get_stat(this->root);
    return create_of("root", p.second, p.first, this->root);
}

open_file
process::of_exe(std::pair<bool, bool> granted)
{
    if (not granted.first and granted.second)
        return create_of("exe", "unknown", 0, this->path + "/exe" + readlink_denied);
    else if (not granted.first)
        return create_of("exe", "unknown", 0, this->path + "/exe");
    std::pair<ino_t, std::string> p = get_stat(this->exe);
    return create_of("exe", p.second, p.first, this->exe);
}

bool
is_deleted(const std::string& f)
{
    std::string deleted = " (deleted)";
    size_t f_len = f.size();
    size_t d_len = deleted.size();
    if (f_len >= d_len and f.compare(f_len - d_len, d_len, deleted) == 0)
        return true;
    else
        return false;
}

bool
is_anon_inode(const std::string& f)
{
    std::string anon_inode = "anon_inode:";
    size_t f_len = f.size();
    size_t a_len = anon_inode.size();
    if (f_len >= a_len and f.compare(0, a_len, anon_inode) == 0)
        return true;
    else
        return false;
}

std::string
rm_error_msg(const std::string& f)
{
    std::string f1 = f;
    size_t f_len = f1.size();
    size_t d_len = deleted.size();
    size_t r_len = readlink_denied.size();
    size_t o_len = opendir_denied.size();
    if (f_len >= d_len and f1.compare(f_len - d_len, d_len, deleted) == 0)
        return f1.erase(f_len - d_len);
    else if (f_len >= r_len and f1.compare(f_len - r_len, r_len, readlink_denied) == 0)
        return f1.erase(f_len - r_len);
    else if (f_len >= o_len and f1.compare(f_len - o_len, o_len, opendir_denied) == 0)
        return f1.erase(f_len - o_len);
    return f1;
}

std::vector<open_file>
process::of_mem(std::pair<bool, bool> granted)
{
    std::vector<open_file> of;
    std::pair<ino_t, std::string> p;
    if (not granted.first)
        return of;
    for (auto m: this->mem) {
        if (is_deleted(m.second)) {
            open_file f = create_of("del", "unknown", m.first, m.second);
            of.push_back(f);
            continue;
        }
        p = get_stat(m.second);
        open_file f = create_of("mem", p.second, m.first, m.second);
        of.push_back(f);
    }
    return of;
}

std::vector<open_file>
process::of_fd(std::pair<bool, bool> granted)
{
    std::vector<open_file> of;
    if (not granted.first and granted.second) {
        open_file f = create_of("NOFD", "", 0, this->path + "/fd" + opendir_denied);
        of.push_back(f);
        return of;
    }
    else if (not granted.first) {
        open_file f = create_of("NOFD", "", 0, this->path + "/fd");
        of.push_back(f);
        return of;
    }
    for (auto f: this->fd) {
        std::stringstream ss;
        std::string fd;
        ss << f;
        ss >> fd;
        std::string path = this->path + "/fd/" + fd;
        ssize_t len = readlink(path.c_str(), buf, sizeof(buf)-1);
        if (len != -1) {
            buf[len] = 0;
            std::string f = buf;
            std::pair<ino_t, std::string> p = get_stat(path);
            std::string m = get_fdinfo(this->path + "/fdinfo/" + fd);
            std::string type;
            std::string name;
            if (is_deleted(f))
                type = "unknown";
            else
                type = p.second;
            if (is_anon_inode(f)) {
                std::stringstream ss;
                std::string inode;
                ss << p.first;
                ss >> inode;
                name = "anon_inode:[" + inode + "]"; 
            } else
                name = f;
            open_file o = create_of(fd + m, type, p.first, name);
            of.push_back(o);
        }
    }
    return of;
}

enum flag
{
    cflag, tflag, fflag
};

class filter
{
public:
    explicit filter(flag f, const std::string& r): fl(f), re(r) {}
    bool operator() (const open_file&);
private:
    flag fl;
    std::regex re;
};

bool
filter::operator() (const open_file& of) {
    bool ret;
    switch (fl) {
    case cflag:
        if (std::regex_search(of.command, re)) ret = true;
        else ret = false;
        break;
    case tflag:
        if (std::regex_match(of.type, re)) ret = true;
        else ret = false;
        break;
    case fflag:
        if (std::regex_search(rm_error_msg(of.name), re)) ret = true;
        else ret = false;
        break;
    default:
        break;
    }
    return ret;
}

class filters
{
public:
    filters(int, char**);
    bool operator() (const open_file&);
private:
    std::vector<filter> fs;
};

filters::filters(int argc, char** argv)
: fs()
{
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "-c") {
            i++;
            if (i < argc) fs.push_back(filter(cflag, argv[i]));
            i++;
        }
        else if (arg == "-t") {
            i++;
            if (i < argc) fs.push_back(filter(tflag, argv[i]));
            i++;
        }
        else if (arg == "-f") {
            i++;
            if (i < argc) fs.push_back(filter(fflag, argv[i]));
            i++;
        }
        else {
            i++;
        }
    }
}

bool
filters::operator() (const open_file& of)
{
    if (fs.size() == 0)
        return true;
    bool ret = true;
    for (auto f: this->fs) {
        ret = ret and f(of);
    }
    return ret;
}

bool
argv_ok(int argc, char** argv)
{
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "-c") {
            i++;
            if (i < argc) i++;
        }
        else if (arg == "-t") {
            i++;
            if (i < argc) {
                std::string arg1 = argv[i];
                if (arg1 != "REG" and arg1 != "CHR" and arg1 != "DIR"
                and arg1 != "FIFO" and arg1 != "SOCK" and arg1 != "unknown") {
                    return false;
                }
                i++;
            } else {
                return false;
            }
        }
        else if (arg == "-f") {
            i++;
            if (i < argc) i++;
        }
        else {
            i++;
        }
    }
    return true;
}

int
main(int argc, char** argv)
{
    if (not argv_ok(argc, argv)) {
        std::cout << "Invalid TYPE option." << "\n";
        exit(1);
    }

    filters fs(argc, argv);

    std::vector<process> processes = process::get_processes();
    std::vector<open_file> of;
    std::vector<open_file> result;

    std::sort(processes.begin(), processes.end());
    for (auto p: processes) {
        std::vector<open_file> f = p.lsof();
        of.insert(of.end(), f.begin(), f.end());
    }

    std::copy_if(of.begin(), of.end(), std::back_inserter(result), fs);

    std::cout << "COMMAND" << " " << "PID" << " " << "USER" << " "
    << "FD" << " " << "TYPE" << " " << "NODE" << " " << "NAME" << "\n";
    for (auto f: result) {
        std::cout << f << "\n";
    }

    return 0;
}