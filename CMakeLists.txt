cmake_minimum_required(VERSION 2.8)

#在项目中显示所有源码
file(GLOB files_src ./src/*.cpp ./src/*.h)

#编译项目所需源码
set(src_app ${files_src})
MESSAGE( STATUS "file = ${files_src}")

#编译参数
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_definitions(-DBOOST_LOCALE_HIDE_AUTO_PTR)

#输出项目名称
project(mdfactory)

add_executable(${PROJECT_NAME} ${src_app})
target_link_libraries (${PROJECT_NAME} pthread)
target_link_libraries (${PROJECT_NAME} libboost_system.a libboost_coroutine.a libboost_context.a)
target_link_libraries (${PROJECT_NAME} libboost_locale.a libboost_thread.a libboost_date_time.a libboost_filesystem.a)
target_link_libraries (${PROJECT_NAME} avcodec avformat avutil)
target_link_libraries (${PROJECT_NAME} libpjsua-x86_64-unknown-linux-gnu.a libpjsip-ua-x86_64-unknown-linux-gnu.a libpjsip-simple-x86_64-unknown-linux-gnu.a libpjsip-x86_64-unknown-linux-gnu.a)
target_link_libraries (${PROJECT_NAME} libpjmedia-videodev-x86_64-unknown-linux-gnu.a libpjmedia-audiodev-x86_64-unknown-linux-gnu.a libpjmedia-codec-x86_64-unknown-linux-gnu.a libpjmedia-x86_64-unknown-linux-gnu.a libsrtp-x86_64-unknown-linux-gnu.a libpjlib-util-x86_64-unknown-linux-gnu.a libpj-x86_64-unknown-linux-gnu.a)