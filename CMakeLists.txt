cmake_minimum_required(VERSION 3.8)
project(arp_spoof)

set(CMAKE_CXX_STANDARD 11)


set(SOURCE_FILES main.cpp arpspoof.h arpspoof.cpp send_arp.h send_arp.cpp)

add_executable(arp_spoof ${SOURCE_FILES})

target_link_libraries(arp_spoof -lpcap -lpthread)