cmake_minimum_required(VERSION 3.16)
# Project name
project(rats-tls-client)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -fPIC -Werror=implicit-function-declaration")
set(CMAKE_C_FLAGS "-fPIE ${CMAKE_C_FLAGS}")

set(RATS_TLS_INSTALL_PATH "/usr/local")

set(RATS_TLS_INSTALL_INCLUDE_PATH "${RATS_TLS_INSTALL_PATH}/include/rats-tls")

set(RATS_TLS_INSTALL_LIB_PATH "${RATS_TLS_INSTALL_PATH}/lib/rats-tls")

set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/edl
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls
                    )
set(LIBRARY_DIRS "/usr/local/lib/rats-tls")

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH $ORIGIN/lib)

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES client.c)

# Generate bin file

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} rats_tls)


install(TARGETS ${PROJECT_NAME}
	DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/../samples)
