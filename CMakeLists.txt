cmake_minimum_required(VERSION 3.10)
project(t1tribes)
# Use C++20
set(CMAKE_CXX_STANDARD 20)

# Include the header files
include_directories(include/)

# Add the cpp files
set(SOURCES src/t1master.cpp)
add_executable(t1tribes ${SOURCES})

if(MSVC)
    # Fail on warnings
    add_compile_options(/W4 /WX)
    # Link the Windows libraries
    target_link_libraries(t1tribes wsock32 ws2_32)

else()
    # Fail on warnings
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()
