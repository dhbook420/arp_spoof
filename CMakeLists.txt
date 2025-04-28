cmake_minimum_required(VERSION 3.10)
project(send_arp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



add_executable(send-arp
        send_arp.cpp
        utils.cpp
        mac.h
        ip.h
        ethhdr.h
        arphdr.h)

target_link_libraries(send-arp pcap)