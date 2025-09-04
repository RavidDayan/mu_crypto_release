/*
 * Test ML-DSA Algorithm Availability in OpenSSL
 * This test verifies if ML-DSA algorithms are available in the current OpenSSL build
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

int main() {
    int result = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    
    printf("ML-DSA Availability Test\n");
    printf("========================\n\n");
    
    // Initialize OpenSSL
    printf("1. Initializing OpenSSL...\n");
    
    // Load default provider
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        printf("   ERROR: Failed to load default provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("   Default provider loaded successfully\n");
    
    // Test ML-DSA-44
    printf("\n2. Testing ML-DSA-44 availability...\n");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
    if (ctx) {
        printf("   SUCCESS: ML-DSA-44 algorithm is available\n");
        EVP_PKEY_CTX_free(ctx);
        result++;
    } else {
        printf("   FAILED: ML-DSA-44 algorithm not available\n");
        ERR_print_errors_fp(stderr);
    }
    
    // Test ML-DSA-65
    printf("\n3. Testing ML-DSA-65 availability...\n");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (ctx) {
        printf("   SUCCESS: ML-DSA-65 algorithm is available\n");
        EVP_PKEY_CTX_free(ctx);
        result++;
    } else {
        printf("   FAILED: ML-DSA-65 algorithm not available\n");
        ERR_print_errors_fp(stderr);
    }
    
    // Test ML-DSA-87
    printf("\n4. Testing ML-DSA-87 availability...\n");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    if (ctx) {
        printf("   SUCCESS: ML-DSA-87 algorithm is available\n");
        EVP_PKEY_CTX_free(ctx);
        result++;
    } else {
        printf("   FAILED: ML-DSA-87 algorithm not available\n");
        ERR_print_errors_fp(stderr);
    }
    
    // Test key generation for ML-DSA-65 as an example
    printf("\n5. Testing ML-DSA-65 key generation...\n");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (ctx) {
        if (EVP_PKEY_keygen_init(ctx) == 1) {
            if (EVP_PKEY_generate(ctx, &pkey) == 1) {
                printf("   SUCCESS: ML-DSA-65 key generation works\n");
                EVP_PKEY_free(pkey);
                result++;
            } else {
                printf("   FAILED: ML-DSA-65 key generation failed\n");
                ERR_print_errors_fp(stderr);
            }
        } else {
            printf("   FAILED: ML-DSA-65 keygen init failed\n");
            ERR_print_errors_fp(stderr);
        }
        EVP_PKEY_CTX_free(ctx);
    }
    
    // Cleanup
    OSSL_PROVIDER_unload(default_prov);
    
    printf("\n========================\n");
    printf("Results: %d/4 tests passed\n", result);
    
    if (result == 4) {
        printf("STATUS: ML-DSA is fully available and functional!\n");
        return 0;
    } else {
        printf("STATUS: ML-DSA support is incomplete or unavailable\n");
        return 1;
    }
}
