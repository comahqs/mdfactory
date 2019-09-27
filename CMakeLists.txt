cmake_minimum_required(VERSION 2.8)

#在项目中显示所有源码
file(GLOB files_src ./src/*.cpp ./src/*.h)

#编译项目所需源码
set(src_app ${files_src})
MESSAGE( STATUS "file = ${files_src}")

SET( CMAKE_CXX_FLAGS "-std=c++11 -gdwarf-4 -g")

#输出项目名称
project(mdfactory)

#include_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/x86_64-w64-mingw32/include")
#include_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/include")
#link_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/x86_64-w64-mingw32/lib")
#link_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/lib")


#link_directories("D:/linux_boost_1_71_0/lib")
#include_directories("D:/linux_boost_1_71_0/include")

add_definitions(-DBOOST_LOCALE_HIDE_AUTO_PTR)
add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
add_definitions(-DPJ_AUTOCONF=1)


add_executable(${PROJECT_NAME} ${src_app})
#target_link_libraries (${PROJECT_NAME} libpj-x86_64-unknown-linux-gnu.a libpjlib-util-x86_64-unknown-linux-gnu.a libpjsip-x86_64-unknown-linux-gnu.a)
#target_link_libraries (${PROJECT_NAME} ws2_32)
#target_link_libraries (${PROJECT_NAME} libboost_system-mgw73-mt-d-x64-1_71.a libboost_coroutine-mgw73-mt-d-x64-1_71.a libboost_context-mgw73-mt-d-x64-1_71.a)
#target_link_libraries (${PROJECT_NAME} libboost_locale-mgw73-mt-d-x64-1_71.a libboost_thread-mgw73-mt-d-x64-1_71.a libboost_date_time-mgw73-mt-d-x64-1_71.a)

target_link_libraries (${PROJECT_NAME}  libpjsua-x86_64-unknown-linux-gnu.a libpjsip-ua-x86_64-unknown-linux-gnu.a libpjsip-simple-x86_64-unknown-linux-gnu.a libpjsip-x86_64-unknown-linux-gnu.a libpjmedia-codec-x86_64-unknown-linux-gnu.a libpjmedia-x86_64-unknown-linux-gnu.a libpjlib-util-x86_64-unknown-linux-gnu.a libpj-x86_64-unknown-linux-gnu.a)
#target_link_libraries (${PROJECT_NAME} ws2_32)
target_link_libraries (${PROJECT_NAME} libboost_system.a libboost_coroutine.a libboost_context.a)
target_link_libraries (${PROJECT_NAME} libboost_locale.a libboost_thread.a libboost_date_time.a)
target_link_libraries (${PROJECT_NAME} pthread)