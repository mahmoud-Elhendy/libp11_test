cmake_minimum_required(VERSION 3.1...3.24)

project(
  libp11_test
  VERSION 1.0
  LANGUAGES CXX)

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)


add_executable(libp11_test main.cpp)

target_link_libraries(libp11_test p11 OpenSSL::Crypto)

install(TARGETS libp11_test DESTINATION ${CMAKE_INSTALL_BINDIR})