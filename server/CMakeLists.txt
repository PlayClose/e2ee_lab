set(target server)
add_executable(${target} ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_include_directories(${target} PUBLIC 
											${CMAKE_SOURCE_DIR}
											${CMAKE_CURRENT_SOURCE_DIR} 
											${CMAKE_INSTALL_INCLUDEDIR}							
							)

target_link_libraries(${target} ${CONAN_LIBS} cryptoapi)
