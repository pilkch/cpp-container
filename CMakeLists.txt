# Set the minimum cmake version
CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

SET(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(CMAKE_CXX_EXTENSIONS ON)

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

# Set the project name
PROJECT(cpp-container)

# Select flags
SET(CMAKE_CXX_FLAGS_RELEASE "-O2")
SET(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")

# Add definitions, compiler switches, etc.
ADD_DEFINITIONS("-std=c++17 -Wall -W -Wextra -Werror -Wformat -Wformat-y2k -Winit-self -Wstack-protector -Wunknown-pragmas -Wundef -Wwrite-strings -Wno-unused-parameter -Wpointer-arith -Wno-switch -Woverloaded-virtual -Wno-stack-protector -Wmissing-include-dirs -Wuninitialized -O2")

# Add executable called "cpp-container" that is built from the source files.
# The executable extension is automatically picked based on the OS.
ADD_EXECUTABLE(cpp-container main.cpp)


# Link our libraries
TARGET_LINK_LIBRARIES(${PROJECT_NAME} cap seccomp)

