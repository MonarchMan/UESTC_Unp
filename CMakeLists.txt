cmake_minimum_required(VERSION 3.16)
project(quic_asio LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
find_package(Threads REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS system)

# ngtcp2
find_package(PkgConfig REQUIRED)
pkg_check_modules(NGTCP2 REQUIRED libngtcp2)
pkg_check_modules(NGTCP2_CRYPTO_GNUTLS REQUIRED libngtcp2_crypto_gnutls)

# GnuTLS
pkg_check_modules(GNUTLS REQUIRED gnutls)

# GoogleTest
find_package(GTest)
if(NOT GTest_FOUND)
    add_subdirectory(/usr/src/googletest googletest)
endif()

include_directories(
    ${Boost_INCLUDE_DIRS}
    ${NGTCP2_INCLUDE_DIRS}
    ${NGTCP2_CRYPTO_GNUTLS_INCLUDE_DIRS}
    ${GNUTLS_INCLUDE_DIRS}
)

link_directories(
    ${NGTCP2_LIBRARY_DIRS}
    ${NGTCP2_CRYPTO_GNUTLS_LIBRARY_DIRS}
    ${GNUTLS_LIBRARY_DIRS}
)

set(COMMON_LIBS
    ${NGTCP2_LIBRARIES}
    ${NGTCP2_CRYPTO_GNUTLS_LIBRARIES}
    ${GNUTLS_LIBRARIES}
    ${Boost_LIBRARIES}
    Threads::Threads
)

set(SERVER_SRC
    src/quic_session.cpp
    src/quic_crypto.cpp
    src/quic_server.cpp
)

set(CLIENT_SRC
    src/quic_session.cpp
    src/quic_crypto.cpp
    src/quic_client.cpp
)

add_executable(quic_server src/main_server.cpp ${SERVER_SRC})
target_link_libraries(quic_server ${COMMON_LIBS})

add_executable(quic_client src/main_client.cpp ${CLIENT_SRC})
target_link_libraries(quic_client ${COMMON_LIBS})

enable_testing()
set(TEST_SRC
    src/quic_session.cpp
    src/quic_crypto.cpp
)

add_executable(quic_tests tests/test_quic.cpp ${TEST_SRC})
target_include_directories(quic_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(quic_tests ${COMMON_LIBS} GTest::gtest_main)
add_test(NAME quic_tests COMMAND quic_tests)
