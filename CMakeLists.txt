cmake_minimum_required(VERSION 3.14)

project(libdquic 
	VERSION 1.0
)

add_subdirectory(deps/cyclone_crypto)


if (STATIC_LIBRARY)
	add_library(dquic STATIC)
else()
	add_library(dquic SHARED)
endif()

target_sources(dquic PRIVATE
	src/quic.c src/quic_crypto.c
	$<TARGET_OBJECTS:cycloneCRYPTO>
	$<TARGET_OBJECTS:cycloneCommon>
)

if (NOT MSVC)
	target_compile_options(dquic PRIVATE -fvisibility=hidden)
endif()

target_compile_options(dquic PRIVATE -fvisibility=hidden)

target_include_directories(dquic 
	PUBLIC
	"${PROJECT_SOURCE_DIR}/include"
	PRIVATE
	"${PROJECT_SOURCE_DIR}/deps/cyclone_crypto"
	"${PROJECT_SOURCE_DIR}/deps/cyclone_common"
	"${PROJECT_SOURCE_DIR}/deps/cyclone_config"
)

set_target_properties(dquic PROPERTIES PUBLIC_HEADER include/dquic.h)

install (TARGETS dquic)


if (NOT NO_TESTING)
	set(CMAKE_CXX_STANDARD 14)
	set(CMAKE_CXX_STANDARD_REQUIRED ON)

	set(INSTALL_GTEST OFF)


	include(FetchContent)
	FetchContent_Declare(
		googletest
		URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip
		DOWNLOAD_EXTRACT_TIMESTAMP 1
	)
	# For Windows: Prevent overriding the parent project's compiler/linker settings
	set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
	FetchContent_MakeAvailable(googletest)


	enable_testing()

	add_executable(
		quic_test 
		tests/quic_decrypt_test.cc
	)
	target_link_libraries(quic_test 
		PRIVATE dquic
		GTest::gtest_main
	)

	add_test(
		NAME quic_decrypt_test
		COMMAND $<TARGET_FILE:quic_test>
	)

	include(GoogleTest)
	gtest_discover_tests(quic_test)
endif (NOT NO_TESTING)
