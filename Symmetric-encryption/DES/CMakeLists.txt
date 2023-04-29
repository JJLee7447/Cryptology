cmake_minimum_required(VERSION 3.24)
project(DES)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(DES
        DES.h
        main.cpp)
