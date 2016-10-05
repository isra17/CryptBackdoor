add_library (disasm disasm-lib/cpu.c
                    disasm-lib/disasm.c
                    disasm-lib/disasm_x86.c
                    disasm-lib/misc.c)
add_library (mhook mhook-lib/mhook.cpp)
add_library (CryptBackdoor SHARED crypt_backdoor.cpp)

target_link_libraries (mhook disasm)
target_link_libraries (CryptBackdoor mhook)

add_definitions (-DUNICODE)
add_definitions (-D_UNICODE)

set (needed_features
     cxx_nullptr)

target_compile_features (CryptBackdoor PRIVATE ${needed_features})

