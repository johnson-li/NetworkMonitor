cmake_minimum_required(VERSION 3.16)
project(NetworkMonitor)

set(CMAKE_CXX_STANDARD 14)

add_executable(NetworkMonitor main.cpp)

target_link_libraries(NetworkMonitor pcap boost_program_options)
