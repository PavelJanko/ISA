cmake_minimum_required(VERSION 3.12)
project(isa)

set(CMAKE_CXX_STANDARD 14)

add_executable(dns-export
        Header.cpp
        Header.h
        main.cpp
        Query.cpp
        Query.h
        Question.cpp
        Question.h
        Record.cpp
        Record.h)

target_link_libraries(dns-export pcap)