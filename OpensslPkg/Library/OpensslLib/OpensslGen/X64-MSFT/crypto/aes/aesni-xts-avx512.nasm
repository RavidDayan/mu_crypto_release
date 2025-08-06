default rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
section .text code align=64

global  aesni_xts_128_encrypt_avx512
global  aesni_xts_128_decrypt_avx512

aesni_xts_128_encrypt_avx512:
aesni_xts_128_decrypt_avx512:
DB      0x0f,0x0b
        DB      0F3h,0C3h               ;repret

global  aesni_xts_256_encrypt_avx512
global  aesni_xts_256_decrypt_avx512

aesni_xts_256_encrypt_avx512:
aesni_xts_256_decrypt_avx512:
DB      0x0f,0x0b
        DB      0F3h,0C3h               ;repret

global  aesni_xts_avx512_eligible

aesni_xts_avx512_eligible:
        xor     eax,eax
        DB      0F3h,0C3h               ;repret


