add_subdirectory(nullverifier)
add_subdirectory(demoverifier)

if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa-qve)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()

if(SGXDCAPQV_FOUND)
    add_subdirectory(sgx-ecdsa)
else()
    message(WARNING "It will not generate libverifier_sgx_ecdsa.so due to libsgx_dcap_quoteverify.so not found in host mode")
endif()