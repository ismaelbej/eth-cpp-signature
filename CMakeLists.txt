cmake_minimum_required(VERSION 3.0.0)
project(eth-cpp-signature VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_executable(eth-cpp-signature main.cpp)

find_library(GMP_LIB gmp REQUIRED)
if (GMP_LIB)
    message(STATUS "Found gmp library at: ${GMP_LIB}")
    target_link_libraries(eth-cpp-signature PRIVATE ${GMP_LIB})
else()
    message(ERROR "gmp library not found")
endif()

find_library(SECP256K1_LIB secp256k1 REQUIRED)
if (SECP256K1_LIB)
    message(STATUS "Found secp256k1 library at: ${SECP256K1_LIB}")
    target_link_libraries(eth-cpp-signature PRIVATE ${SECP256K1_LIB})
else()
    message(ERROR "secp256k1 library not found")
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
