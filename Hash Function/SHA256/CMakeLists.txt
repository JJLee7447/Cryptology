cmake_minimum_required(VERSION 3.25)
project(SHA256)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(SHA256
        main.cpp
        SHA256.cpp
        SHA256.h)
