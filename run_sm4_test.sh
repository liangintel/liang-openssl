gcc -O3 -march=native -std=c11 -Wall -Wextra -Iinclude -I. test/gcm_sm4_path_bench.c crypto/sm4/libcrypto-shlib-sm4-x86_64.o -o test/gcm_sm4_path_bench_real

./test/gcm_sm4_path_bench_real 1048576 80

