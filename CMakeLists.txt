cmake_minimum_required(VERSION 3.12)
project(isa)

set(CMAKE_CXX_STANDARD 14)

add_executable(dns-export
        main.cpp)
target_link_libraries(dns-export pcap)
