cmake_minimum_required(VERSION 3.28)

project(api_hasher) 

set(CMAKE_CXX_STANDARD 20)
set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON) 
set(Boost_USE_MULTITHREADED ON)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
endif()

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /permissive-")
endif()

find_package(
	Boost 1.81
	REQUIRED
)
include_directories(${Boost_INCLUDE_DIRS})
 
add_library(api_hash)
target_sources(api_hash
  PUBLIC
    FILE_SET CXX_MODULES FILES
     ${CMAKE_CURRENT_LIST_DIR}/source/api_hasher.ixx
	 "source/hash_functions.ixx"
)
#target_link_libraries(filehash PRIVATE ${Boost_LIBRARIES})

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/source/main.cpp) 
target_link_libraries(main PRIVATE api_hash) 
