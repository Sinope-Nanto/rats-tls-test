# Set include directory

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -fPIC -Werror=implicit-function-declaration")
set(RATS_TLS_LDFLAGS "-fPIC -Bsymbolic -ldl")

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()

include(LibCBOR.cmake)

# /usr/local
set(RATS_TLS_INSTALL_PATH "/usr/local")

# lib/rats_tls
set(RATS_TLS_INSTALL_LIB_PATH "${RATS_TLS_INSTALL_PATH}/lib/rats-tls")

# rats_tls/crypto-wrappers
set(RATS_TLS_INSTALL_LIBCW_PATH "${RATS_TLS_INSTALL_LIB_PATH}/crypto-wrappers")

# rats_tls/attesters
set(RATS_TLS_INSTALL_LIBA_PATH "${RATS_TLS_INSTALL_LIB_PATH}/attesters")

# rats_tls/verifiers
set(RATS_TLS_INSTALL_LIBV_PATH "${RATS_TLS_INSTALL_LIB_PATH}/verifiers")

# rats_tls/tls-wrappers
set(RATS_TLS_INSTALL_LIBTW_PATH "${RATS_TLS_INSTALL_LIB_PATH}/tls-wrappers")

set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/internal
                 /opt/intel/sgxsdk/include
                 /usr/include
                 )

# Add third party and instance directory
add_subdirectory(attesters)
add_subdirectory(verifiers)

# Add third party library required by crypto_wrappers and tls_wrappers

add_subdirectory(crypto_wrappers)
add_subdirectory(tls_wrappers)

list(APPEND INCLUDE_DIRS ${LIBCBOR_INC_PATH})

include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rtls_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rtls_core_generate_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/cpu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/dice.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/endorsement.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/claim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_cleanup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_negotiate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_receive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_transmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_callback.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/api/crypto_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/rtls_crypto_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/rtls_crypto_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/rtls_crypto_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/tls_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/api/enclave_attester_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/enclave_attester.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rtls_enclave_attester_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rtls_enclave_attester_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rtls_enclave_attester_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/api/enclave_verifier_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/enclave_verifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rtls_enclave_verifier_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rtls_enclave_verifier_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rtls_enclave_verifier_select.c
    )

# Generate librar

set(RTLS_LIB rats_tls)

add_library(${RTLS_LIB} SHARED ${SOURCES})
add_dependencies(${RTLS_LIB} libcbor)
target_link_libraries(${RTLS_LIB} ${RATS_TLS_LDFLAGS} ${LIBCBOR_LIB_FILES})
set_target_properties(${RTLS_LIB} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})


# Install lib
install(TARGETS ${RTLS_LIB}
    DESTINATION ${RATS_TLS_INSTALL_LIB_PATH})

# Install header
set(RTLS_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/api.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/cert.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/crypto_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/attester.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/verifier.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/err.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/log.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/sgx.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/tls_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/hash.h
                       )

set(RATS_TLS_INSTALL_INCLUDE_PATH "/usr/local/include")
install(DIRECTORY DESTINATION ${RATS_TLS_INSTALL_INCLUDE_PATH}/rats-tls)
install(FILES ${RTLS_INCLUDE_FILES}
DESTINATION ${RATS_TLS_INSTALL_INCLUDE_PATH}/rats-tls)
