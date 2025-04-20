set(target cryptoapi)

add_library(${target} SHARED #${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
							${CMAKE_CURRENT_SOURCE_DIR}/openssl_dh.cpp
							${CMAKE_CURRENT_SOURCE_DIR}/certificate.cpp
							${CMAKE_CURRENT_SOURCE_DIR}/misc.cpp
							${CMAKE_CURRENT_SOURCE_DIR}/aes/ctaes.c
							${CMAKE_CURRENT_SOURCE_DIR}/aes/aes.cpp)
message("libdir: ${CMAKE_SOURCE_DIR}")
set_target_properties(${target} PROPERTIES
  CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

target_include_directories(${target} PUBLIC 
										${CMAKE_CURRENT_SOURCE_DIR}
										${CMAKE_CURRENT_SOURCE_DIR}/aes
							)
find_package(OpenSSL)
if (OPENSSL_FOUND)
message (STATUS "OPENSSL found")
message (STATUS "OpenSSL INclude directories:" OPENSSL_INCLUDE_DIR)
else() 
message (FATAL_ERROR "OpenSSL Not found.")
endif()

include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(${target} ${OPENSSL_LIBRARIES})
target_link_libraries(${target} ${CONAN_LIBS})

#install(TARGETS FILE_SET HEADERS)
