cmake_minimum_required (VERSION 3.8)

project ("TrySeal")

#告诉CMake那里去找你的SEAL库
set(SEAL_DIR /usr/local/lib64/)

#去找SEAL库
find_package(SEAL 3.7 REQUIRED)

# 将源代码添加到此项目的可执行文件。
add_executable (TrySeal "trySeal.cpp" "trySeal.h")

#包含文件路径
include_directories("/usr/local/include/SEAL-3.7/")

# 将SEAL库链接到该项目
target_link_libraries(TrySeal SEAL::seal_shared)
# TODO: 如有需要，请添加测试并安装目标。
