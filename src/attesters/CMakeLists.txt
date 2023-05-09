add_subdirectory(nullattester)
add_subdirectory(demoattester)

# if(OCCLUM OR SGX)
#     add_subdirectory(sgx-ecdsa)
# endif()

# if(SGX)
#     add_subdirectory(sgx-la)
# endif()

# if(EXISTS "/usr/include/linux/sev-guest.h")
#     add_subdirectory(sev-snp)
# endif()
add_subdirectory(sgx-ecdsa-qve)
add_subdirectory(sgx-la)