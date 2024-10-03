cmake_minimum_required(VERSION 3.29)
project(IDS)

set(CMAKE_CXX_STANDARD 20)

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})

add_executable(IDS main.cpp)
target_link_libraries(IDS pcap ${CURL_LIBRARIES})