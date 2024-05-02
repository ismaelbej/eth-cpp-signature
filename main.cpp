#include <iostream>
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

// Helper function to convert hex string to byte array.
int hex_to_bytes(unsigned char *byte_array, const char *hex_string, size_t byte_array_max_len) {
    size_t hex_len = strlen(hex_string);
    if (hex_len % 2 != 0 || byte_array_max_len < hex_len / 2) return 0;
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex_string + 2 * i, "%2hhx", &byte_array[i]);
    }
    return 1;
}

int main() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char private_key[32];
    unsigned char message_hash[32]; // The hash of your message.

    // Dummy private key and message hash (normally you would compute the hash of your message)
    hex_to_bytes(private_key, "0101010101010101010101010101010101010101010101010101010101010101", sizeof(private_key));
    hex_to_bytes(message_hash, "0202020202020202020202020202020202020202020202020202020202020202", sizeof(message_hash));

    secp256k1_ecdsa_recoverable_signature signature;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &signature, message_hash, private_key, NULL, NULL)) {
        fprintf(stderr, "Failed to sign the message.\n");
        return 1;
    }
    printf("Signature: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", signature.data[i]);
    }

    // Serialize the signature in compact format
    unsigned char output[64];
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output, &recid, &signature);

    printf("\nSignature: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", output[i]);
    }
    printf("\nRecovery ID: %d\n", recid);

    secp256k1_context_destroy(ctx);
    return 0;
}
