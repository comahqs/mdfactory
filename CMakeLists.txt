cmake_minimum_required(VERSION 2.8)

#在项目中显示所有源码
file(GLOB files_src ./src/*.cpp ./src/*.h)

#编译项目所需源码
set(src_app ${files_src})
MESSAGE( STATUS "file = ${files_src}")

#输出项目名称
project(mdfactory)

include_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/x86_64-w64-mingw32/include")
include_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/include")
link_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/x86_64-w64-mingw32/lib")
link_directories("C:/Qt/Qt5.12.2/Tools/mingw730_64/lib")

include_directories("D:/boost_1_71_0")
link_directories("D:/boost_1_71_0/lib/mingw64")

add_executable(${PROJECT_NAME} ${src_app})
target_link_libraries (${PROJECT_NAME})
