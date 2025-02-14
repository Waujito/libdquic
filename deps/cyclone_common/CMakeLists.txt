add_library(cycloneCommon 
	date_time.c
	debug.c
	str.c
	cpu_endian.c
	resource_manager.c
	path.c

	# os_port_chibios.c
	# os_port_threadx.c
	# os_port_cmsis_rtos.c
	# os_port_freertos.c
	# os_port_zephyr.c
	# os_port_safertos.c
	# os_port_ucos3.c
	# os_port_windows.c
	# os_port_rtx.c
	# os_port_embos.c
	# os_port_none.c
	os_port_posix.c
	# os_port_px5.c
	# os_port_cmsis_rtos2.c
	# os_port_sys_bios.c
	# os_port_ucos2.c
	# os_port_cmx_rtx.c

	# fs_port_fatfs.c
	# fs_port_rl_fs.c
	# fs_port_posix.c
)

target_include_directories(cycloneCommon PUBLIC ${PROJECT_SOURCE_DIR}/deps/cyclone_common ${PROJECT_SOURCE_DIR}/deps/cyclone_config)
