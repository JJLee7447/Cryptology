cmake_minimum_required(VERSION 3.24)
project(AES)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(AES
        AES.cpp
        AES.h
        main.cpp)
