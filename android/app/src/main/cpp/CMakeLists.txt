cmake_minimum_required(VERSION 3.22.1)
project("adiza")

add_library(venom SHARED native_api.cpp)

target_compile_options(venom PRIVATE
    -std=c++17
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
)

find_library(log-lib log)
target_link_libraries(venom ${log-lib})
