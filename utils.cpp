#include <cstdio>
#include "ip.h"
#include "mac.h"

Mac::Mac(const std::string& r) {
    std::string s;
    for(char ch: r) {
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
            s += ch;
    }
    int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
    if (res != Size) {
        fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
        return;
    }
}

Mac::operator std::string() const {
    char buf[20]; // enough size
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
    return std::string(buf);
}

Mac Mac::randomMac() {
    Mac res;
    for (int i = 0; i < Size; i++)
        res.mac_[i] = uint8_t(rand() % 256);
    res.mac_[0] &= 0x7F;
    return res;
}

Mac& Mac::nullMac() {
    static uint8_t _value[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static Mac res(_value);
    return res;
}

Mac& Mac::broadcastMac() {
    static uint8_t _value[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static Mac res(_value);
    return res;
}

Ip::Ip(const std::string r) {
    unsigned int a, b, c, d;
    int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
    if (res != Size) {
        fprintf(stderr, "invalid Ip format %s\n", r.c_str());
        exit(EXIT_FAILURE);
    }
    ip_ = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip::operator std::string() const {
    char buf[32]; // enough size
    sprintf(buf, "%u.%u.%u.%u",
        (ip_ & 0xFF000000) >> 24,
        (ip_ & 0x00FF0000) >> 16,
        (ip_ & 0x0000FF00) >> 8,
        (ip_ & 0x000000FF));
    return std::string(buf);
}
