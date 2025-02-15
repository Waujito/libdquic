add_library(cycloneCommon 
	date_time.c
	debug.c
	str.c
	cpu_endian.c
	resource_manager.c
	path.c
)

if (UNIX)
MESSAGE("Using POSIX os port")
target_sources(
	cycloneCommon
	PRIVATE os_port_posix.c
)
elseif (WIN32)
MESSAGE("Using WIN32 os port")
target_sources(
	cycloneCommon
	PRIVATE os_port_windows.c
)
else()
MESSAGE("Using NONE os port")
target_sources(
	cycloneCommon
	PRIVATE os_port_none.c
)
endif()

target_include_directories(cycloneCommon PUBLIC ${PROJECT_SOURCE_DIR}/deps/cyclone_common ${PROJECT_SOURCE_DIR}/deps/cyclone_config)
