#include "./keccak-tiny.h"
#include <iostream>
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
// #include <openssl/evp.h>
// #include <openssl/core_names.h>

// Helper function to convert hex string to byte array.
int hex_to_bytes(unsigned char *byte_array, const char *hex_string, size_t byte_array_max_len) {
    size_t hex_len = strlen(hex_string);
    if (hex_len % 2 != 0 || byte_array_max_len < hex_len / 2) return 0;
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex_string + 2 * i, "%2hhx", &byte_array[i]);
    }
    return 1;
}

int sign_message(unsigned char private_key[], unsigned char message_hash[]) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_ecdsa_recoverable_signature signature;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &signature, message_hash, private_key, NULL, NULL)) {
        fprintf(stderr, "Failed to sign the message.\n");
        return 1;
    }

    // Serialize the signature in compact format
    unsigned char output[64];
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output, &recid, &signature);

    printf("Signature: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", output[i]);
    }
    printf("\nRecovery ID: %d\n", recid);

    secp256k1_context_destroy(ctx);
    return 0;
}

int hash_message(unsigned char message_hash[]) {
    unsigned char hashed[32];
    uint32_t length;

    keccak_256(hashed, 32, message_hash, 32);

    // EVP_MD_CTX* context = EVP_MD_CTX_new();
    // auto md = EVP_get_digestbyname("KECCAK-256");
    // const EVP_MD* algorithm = EVP_sha3_256();
    // EVP_DigestInit_ex2(context, algorithm, nullptr);
    // EVP_DigestUpdate(context, message_hash, 32);
    // EVP_DigestFinal_ex(context, hashed, &length);
    // EVP_MD_CTX_destroy(context);

    printf("Hashed: ");
    for (int i = 0; i < length; i++) {
        printf("%02x", hashed[i]);
    }
    printf("\n");
    return 0;
}

int main() {
    unsigned char private_key[32];
    unsigned char message_hash[32]; // The hash of your message.

    // OpenSSL_add_all_digests();

    // Dummy private key and message hash (normally you would compute the hash of your message)
    hex_to_bytes(private_key, "0101010101010101010101010101010101010101010101010101010101010101", sizeof(private_key));
    hex_to_bytes(message_hash, "0202020202020202020202020202020202020202020202020202020202020202", sizeof(message_hash));

    // sign_message(private_key, message_hash);

    hash_message(message_hash);
}
