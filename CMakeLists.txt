cmake_minimum_required(VERSION 3.16)
project(bank_psi CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native")

# ---- libsodium ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_library(psi_core STATIC core/psi_core.cpp)
target_include_directories(psi_core PUBLIC core ${SODIUM_INCLUDE_DIRS})
target_link_directories(psi_core PUBLIC ${SODIUM_LIBRARY_DIRS})
target_link_libraries(psi_core PUBLIC ${SODIUM_LIBRARIES})

add_executable(psi_server server/psi_server.cpp)
target_include_directories(psi_server PRIVATE deps core)
target_link_libraries(psi_server PRIVATE psi_core)
find_package(Threads REQUIRED)
target_link_libraries(psi_server PRIVATE Threads::Threads)

# 正确性自测: 小规模两方模拟, 校验交集与明文基准一致
add_executable(psi_selftest tools/selftest.cpp)
target_link_libraries(psi_selftest PRIVATE psi_core)
