cmake_minimum_required(VERSION 3.10)
project(MacOS_flasher C)

set(CMAKE_C_STANDARD 11)

add_executable(MacOS_flasher main.c)

target_link_libraries(MacOS_flasher bcrypt)
