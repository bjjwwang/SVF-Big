cmake -S . -B build-bc -DCMAKE_C_COMPILER=clang -DZLIB_BUILD_WPCB=ON -DZLIB_BUILD_EXAMPLES=OFF
cmake --build build-bc --target whole_program_bc -j