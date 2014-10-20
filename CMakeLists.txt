cmake_minimum_required(VERSION 2.8)

project(venom C)

set(VENOM_VERSION_MAJOR 0)
set(VENOM_VERSION_MINOR 6)


option(BUILD_TESTING "build test" OFF)


if (UNIX)
  set(CMAKE_C_FLAGS "-std=gnu99 -Wall -pedantic -O2")
endif ()


# add library source code
#
add_subdirectory(src)


# add test source if requested
#
if (BUILD_TESTING)
  enable_testing()
  add_subdirectory(test)
endif ()
