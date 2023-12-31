cmake_minimum_required(VERSION 3.28)

project(api_hasher)

set(CMAKE_CXX_STANDARD 20)
set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
#set(Boost_USE_STATIC_LIBS ON) set(Boost_USE_STATIC_RUNTIME ON) 
set(Boost_USE_MULTITHREADED ON)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
set(Boost_DEBUG ON)

if(MSVC)
	set(
	common_compile_options
	/utf-8
	/permissive-
	/volatile:iso
	/Zc:__cplusplus
	/Zc:inline
	/Zc:enumTypes
	/Zc:externConstexpr
	/Zc:lambda
	/Zc:preprocessor
	/Zc:throwingNew
	/diagnostics:caret
	/W4
	/WX
	/w44062
	/w44165
	/w44242
	/w44254
	/w44263
	/w44264
	/w44265
	/w44287
	/w44296
	/w44355
	/w44365
	/w44388
	/w44577
	/w44623
	/we4774
	/we4777
	/w44800
	/w44826
	/we4905
	/we4906
	/w45204
	)
else()
  message(WARNING "THIS IS A MSVC ONLY PROJECT")
endif()

add_library(api_hash)
target_sources(api_hash
  PUBLIC
    FILE_SET CXX_MODULES FILES
     ${CMAKE_CURRENT_LIST_DIR}/src/api_hasher.ixx
	 ${CMAKE_CURRENT_LIST_DIR}/src/hash_functions.ixx
)
target_compile_options(api_hash PRIVATE ${common_compile_options})


add_executable(main "examples/main.cpp") 
target_link_libraries(main PRIVATE api_hash) 
target_compile_options(main PRIVATE ${common_compile_options})
 
enable_testing()
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
add_executable(testing_api_hash "tests/test_api_hash.cpp")
target_link_libraries(testing_api_hash PRIVATE api_hash GTest::gtest GTest::gtest_main GTest::gmock GTest::gmock_main)
target_compile_options(testing_api_hash PRIVATE ${common_compile_options})
add_test(testingapihash testing_api_hash)

# Warn if the user invokes CMake directly
if (SKBUILD)
	message(WARNING "\
	This CMake file is meant to be executed using 'scikit-build-core'.
	Running it directly will almost certainly not produce the desired
	result. If you are a user trying to install this package, use the
	command below, which will install all necessary build dependencies,
	compile the package in an isolated environment, and then install it.
	=====================================================================
	$ pip install .
	=====================================================================
	If you are a software developer, and this is your own package, then
	it is usually much more efficient to install the build dependencies
	in your environment once and use the following command that avoids
	a costly creation of a new virtual environment at every compilation:
	=====================================================================
	$ pip install nanobind scikit-build-core[pyproject]
	$ pip install --no-build-isolation -ve .
	=====================================================================
	You may optionally add -Ceditable.rebuild=true to auto-rebuild when
	the package is imported. Otherwise, you need to rerun the above
	after editing C++ files.")
	find_package(Python
	REQUIRED COMPONENTS Interpreter Development.Module
	OPTIONAL_COMPONENTS Development.SABIModule
	)

	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ext/nanobind)
	find_package(nanobind REQUIRED)
	  nanobind_add_module(
	  api_hash_ext 
	  STABLE_ABI
	  NB_STATIC
	  ${CMAKE_CURRENT_LIST_DIR}/src/api_hash_ext.cpp
	)
	target_link_libraries(api_hash_ext PRIVATE api_hash)
	install(TARGETS api_hash_ext LIBRARY DESTINATION api_hash)
endif()