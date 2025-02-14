cmake_minimum_required(VERSION 3.14)

project(libdquic 
	VERSION 1.0
	LANGUAGES C CXX
)

add_subdirectory(deps/cyclone_crypto)

add_library(dquic STATIC src/quic.c src/quic_crypto.c)

target_link_libraries(dquic PUBLIC cycloneCRYPTO)
target_include_directories(dquic PUBLIC
	"${PROJECT_SOURCE_DIR}/include")


set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


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
	PUBLIC dquic
	GTest::gtest_main
)

add_test(
	NAME quic_decrypt_test
	COMMAND $<TARGET_FILE:quic_test>
)

include(GoogleTest)
gtest_discover_tests(quic_test)
