add_subdirectory(nullattester)
add_subdirectory(demoattester)

# if(OCCLUM OR SGX)
#     add_subdirectory(sgx-ecdsa)
# endif()

# if(SGX)
#     add_subdirectory(sgx-la)
# endif()

add_subdirectory(sgx-ecdsa)
add_subdirectory(sgx-la)