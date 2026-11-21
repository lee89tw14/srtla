cmake_minimum_required(VERSION 3.16)
project(srtla_rec VERSION 1.0.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

find_package(spdlog REQUIRED)

# Core library: the daemon's logic, split into focused modules. main.cpp is a
# thin entrypoint that links against this.
add_library(srtla_core STATIC
    src/proto/protocol.cpp
    src/core/state.cpp
    src/core/conn.cpp
    src/core/auth_throttle.cpp
    src/core/registry.cpp
    src/net/socket_util.cpp
    src/net/srt_handler.cpp
    src/net/srtla_handler.cpp)
target_include_directories(srtla_core PUBLIC src)
target_link_libraries(srtla_core PUBLIC spdlog::spdlog)
target_compile_features(srtla_core PUBLIC cxx_std_17)

# The daemon: thin entrypoint wiring the core together.
add_executable(srtla_rec src/main.cpp)
target_include_directories(srtla_rec PRIVATE deps/argparse/include)
target_link_libraries(srtla_rec PRIVATE srtla_core)
target_compile_definitions(srtla_rec PRIVATE VERSION="${CMAKE_PROJECT_VERSION}")

# Self-check, not part of the default build: make test_auth_throttle && ./test_auth_throttle
add_executable(test_auth_throttle EXCLUDE_FROM_ALL src/core/test_auth_throttle.cpp)
target_link_libraries(test_auth_throttle PRIVATE srtla_core)
target_compile_options(test_auth_throttle PRIVATE -UNDEBUG) # the checks are assert()s

install(TARGETS srtla_rec)
