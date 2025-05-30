cmake_minimum_required(VERSION 3.20)

project(BuddySystem)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER gcc)

add_compile_options(-Werror -Wfatal-errors -Wall -Wextra -Wno-unused-function -g3 -O0)

add_executable(test_buddy test_buddy.c buddy.c buddy.h list.h)

