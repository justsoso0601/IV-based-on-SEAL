# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/light/code/src/IV-based-on-SEAL

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/light/code/src/IV-based-on-SEAL/build

# Include any dependencies generated for this target.
include CMakeFiles/TrySeal.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/TrySeal.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/TrySeal.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TrySeal.dir/flags.make

CMakeFiles/TrySeal.dir/trySeal.cpp.o: CMakeFiles/TrySeal.dir/flags.make
CMakeFiles/TrySeal.dir/trySeal.cpp.o: ../trySeal.cpp
CMakeFiles/TrySeal.dir/trySeal.cpp.o: CMakeFiles/TrySeal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/light/code/src/IV-based-on-SEAL/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/TrySeal.dir/trySeal.cpp.o"
	/opt/rh/devtoolset-10/root/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TrySeal.dir/trySeal.cpp.o -MF CMakeFiles/TrySeal.dir/trySeal.cpp.o.d -o CMakeFiles/TrySeal.dir/trySeal.cpp.o -c /home/light/code/src/IV-based-on-SEAL/trySeal.cpp

CMakeFiles/TrySeal.dir/trySeal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/TrySeal.dir/trySeal.cpp.i"
	/opt/rh/devtoolset-10/root/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/light/code/src/IV-based-on-SEAL/trySeal.cpp > CMakeFiles/TrySeal.dir/trySeal.cpp.i

CMakeFiles/TrySeal.dir/trySeal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/TrySeal.dir/trySeal.cpp.s"
	/opt/rh/devtoolset-10/root/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/light/code/src/IV-based-on-SEAL/trySeal.cpp -o CMakeFiles/TrySeal.dir/trySeal.cpp.s

# Object files for target TrySeal
TrySeal_OBJECTS = \
"CMakeFiles/TrySeal.dir/trySeal.cpp.o"

# External object files for target TrySeal
TrySeal_EXTERNAL_OBJECTS =

TrySeal: CMakeFiles/TrySeal.dir/trySeal.cpp.o
TrySeal: CMakeFiles/TrySeal.dir/build.make
TrySeal: /usr/local/lib64/libseal.so.3.7.2
TrySeal: CMakeFiles/TrySeal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/light/code/src/IV-based-on-SEAL/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable TrySeal"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TrySeal.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TrySeal.dir/build: TrySeal
.PHONY : CMakeFiles/TrySeal.dir/build

CMakeFiles/TrySeal.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TrySeal.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TrySeal.dir/clean

CMakeFiles/TrySeal.dir/depend:
	cd /home/light/code/src/IV-based-on-SEAL/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/light/code/src/IV-based-on-SEAL /home/light/code/src/IV-based-on-SEAL /home/light/code/src/IV-based-on-SEAL/build /home/light/code/src/IV-based-on-SEAL/build /home/light/code/src/IV-based-on-SEAL/build/CMakeFiles/TrySeal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TrySeal.dir/depend

