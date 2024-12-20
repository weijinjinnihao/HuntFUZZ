#ifndef INCLUDE_COMMONUTILS_HPP__
#define INCLUDE_COMMONUTILS_HPP__

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <set>
#include <string>
#include <vector>

unsigned BKDRHash(const char* str) {
    unsigned seed = 1313;  // 31 131 1313 13131 131313 etc..
    unsigned key = 0;
    while (*str) {
        key = key * seed + (*str++);
    }
    return key;
}

inline bool endswith(const std::string& s, const std::string& tail) {
    return s.size() >= tail.size() && s.compare(s.size() - tail.size(), tail.size(), tail) == 0;
}

inline bool startswith(const std::string& s, const std::string& head) {
    return s.size() >= head.size() && s.compare(0, head.size(), head) == 0;
}

uint32_t randomSeed() {
    struct timespec curtime;
    clock_gettime(CLOCK_REALTIME, &curtime);
    return curtime.tv_sec ^ curtime.tv_nsec ^ getpid();
}

bool isEnableEnv(const char* name) {
    char* enable = getenv(name);
    return enable && !strcmp(enable, "1");
}

bool isDisableEnv(const char* name) {
    char* enable = getenv(name);
    return enable && !strcmp(enable, "0");
}
inline bool likely(bool x) {
    return __builtin_expect(x, 1);
}
inline bool unlikely(bool x) {
    return __builtin_expect(x, 0);
}

inline int getTerminalWidth() {
    struct winsize w;
    return ioctl(STDOUT_FILENO, TIOCGWINSZ, &w)?80:w.ws_col;
}

template <class T>
std::string join(T& val, std::string delim)
{
    std::string str;
    typename T::iterator it;
    const typename T::iterator itlast = val.end()-1;
    for (it = val.begin(); it != val.end(); it++)
    {
        str += *it;
        if (it != itlast)
        {
            str += delim;
        }
    }
    return str;
}

// Although <boost/algorithm/string.hpp> may help.
void replace(std::string& str, const std::string& src, const std::string& dest)
{
    using namespace std;
    string::size_type srclen = src.length();
    if(!srclen) return;

    string::size_type loc = str.find(src);
    while(loc != string::npos) {
        str.replace(loc, srclen, dest);
        loc=str.find(src,loc+1);
    }
}

void trim(std::string& str) {
    str.erase(0, str.find_first_not_of(" \t\n\r"));
    str.erase(str.find_last_not_of(" \t\n\r")+1);
}

#endif