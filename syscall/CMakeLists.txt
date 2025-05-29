cmake_minimum_required(VERSION 3.20)

project(BuddySystem)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS -m32)

add_compile_options(-Werror -Wfatal-errors -Wall -Wextra -Wno-unused-function)

add_executable(read_int80 read_int80.c)
target_link_options(read_int80 PRIVATE -static)

