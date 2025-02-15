add_subdirectory(../cyclone_common ../cyclone_common)

add_library(cycloneCRYPTO STATIC
	cipher_modes/ecb.c
	kdf/hkdf.c
	mac/hmac.c
	aead/gcm.c
	hash/sha256.c
	cipher/aes.c

	$<TARGET_OBJECTS:cycloneCommon>
)

target_include_directories(cycloneCRYPTO 
	PUBLIC 
	${PROJECT_SOURCE_DIR}/deps/cyclone_crypto
	PRIVATE
	${PROJECT_SOURCE_DIR}/deps/cyclone_common 
	${PROJECT_SOURCE_DIR}/deps/cyclone_config 
)

target_compile_options(cycloneCRYPTO PRIVATE -fvisibility=hidden)
