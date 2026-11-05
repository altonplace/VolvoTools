cmake_minimum_required(VERSION 3.16)
project(RamDump VERSION 1.0.0 LANGUAGES CXX)

find_package(Easyloggingpp REQUIRED)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} src/RamDump.cpp)

if (WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

target_link_libraries(${PROJECT_NAME}
    Common
    j2534
    easyloggingpp::easyloggingpp
)
