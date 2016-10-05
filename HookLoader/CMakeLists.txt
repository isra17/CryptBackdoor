set (CMAKE_EXE_LINKER_FLAGS "-static")
set (CMAKE_CXX_FLAGS "-municode")
add_executable(HookLoader main.cpp)

add_definitions (-DUNICODE)
add_definitions (-D_UNICODE)

set_property (TARGET HookLoader PROPERTY CXX_STANDARD 11)
set_property (TARGET HookLoader PROPERTY CXX_STANDARD_REQUIRED ON)
