cmake_minimum_required(VERSION 3.20)
project(proxy-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(Boost_NO_BOOST_CMAKE ON)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(proxy-cpp main.cpp)
target_link_libraries(proxy-cpp PRIVATE Boost::system pthread)

