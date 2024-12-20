# set(CMAKE_BUILD_TYPE "Debug")
# llvm cmake

find_package(LLVM 12.0 REQUIRED CONFIG)
message("LLVM STATUS:
  Definitions ${LLVM_DEFINITIONS}
  Includes    ${LLVM_INCLUDE_DIRS}
  Libraries   ${LLVM_LIBRARY_DIRS}
  Targets     ${LLVM_TARGETS_TO_BUILD}
  Version     ${LLVM_PACKAGE_VERSION}"
)

set(Boost_USE_STATIC_LIBS   ON)
find_package(Boost 1.70.0 REQUIRED COMPONENTS program_options)


# if(NOT ${LLVM_ENABLE_RTTI})
#     if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang" OR
#             "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
#             "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
#         set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
#         message(STATUS "Disable RTTI")
#     elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
#         set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GR-")
#         message(STATUS "Disable RTTI")
#     endif()
# endif()

add_definitions(${LLVM_DEFINITIONS})
include_directories(
    include
    ${LLVM_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIR}
)

link_directories(${LLVM_LIBRARY_DIRS})
link_libraries(${Boost_LIBRARIES})

llvm_map_components_to_libnames(LLVM_LIBS bitreader bitwriter interpreter core irreader mcjit native option support)


add_executable(ErrorFinder ${CMAKE_CURRENT_SOURCE_DIR}/ErrorFinder.cc ${CMAKE_CURRENT_SOURCE_DIR}/alias_flow_insensitive.cpp)
target_link_libraries(ErrorFinder ${LLVM_LIBS})
target_link_libraries(ErrorFinder -static-libgcc -static-libstdc++)
