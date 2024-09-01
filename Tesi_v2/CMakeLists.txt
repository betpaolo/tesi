cmake_minimum_required(VERSION 3.5.0)
project(HEPowerConsumption VERSION 0.1.0 LANGUAGES C CXX)

add_executable(HEPowerConsumption main.cpp)

set(CMAKE_BUILD_TYPE Debug)

find_package(SEAL)
target_link_libraries(HEPowerConsumption SEAL::seal)
find_package(OpenSSL REQUIRED)
target_link_libraries(HEPowerConsumption OpenSSL::SSL)