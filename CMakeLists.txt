cmake_minimum_required(VERSION 3.26)
project(CapstoneUnicorn)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(3rd_party/capstone)
add_subdirectory(3rd_party/unicorn)

add_executable(testCapstone testCapstone.cpp)
target_link_libraries(testCapstone PRIVATE capstone::capstone)

add_executable(testUnicorn testUnicorn.cpp)
target_link_libraries(testUnicorn PRIVATE unicorn)
