cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(ChatListener VERSION 1.0 LANGUAGES CXX)

include(FetchContent)
FetchContent_Declare(
  jwt
  GIT_REPOSITORY "https://github.com/Thalhammer/jwt-cpp"
  GIT_TAG        "master"
)
FetchContent_MakeAvailable(jwt)
find_package(nlohmann_json REQUIRED)
find_package(sioclient REQUIRED)

add_executable(ChatListener main.cpp
    config.h config.cpp)

target_link_libraries(ChatListener PRIVATE nlohmann_json)
target_link_libraries(ChatListener PRIVATE sioclient)
target_link_libraries(ChatListener PRIVATE jwt-cpp::jwt-cpp)

set_property(TARGET ChatListener PROPERTY CXX_STANDARD 23)
