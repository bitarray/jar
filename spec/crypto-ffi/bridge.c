/*
 * C bridge between Lean 4 runtime objects and Rust crypto FFI functions.
 *
 * Each LEAN_EXPORT function matches an @[extern "name"] declaration in Jar/Crypto.lean.
 * These functions marshal Lean ByteArray/OctetSeq objects to raw byte pointers,
 * call the corresponding jar_ffi_* Rust function, and wrap the result back.
 */

#include <lean/lean.h>
#include <string.h>
#include <stdlib.h>
#include "sizes.h"

/* Compile-time size sanity checks */
_Static_assert(JAR_HASH_SIZE == 32, "Hash size must be 32");
_Static_assert(JAR_ED25519_PUBKEY_SIZE == 32, "Ed25519 public key must be 32");
_Static_assert(JAR_ED25519_SIG_SIZE == 64, "Ed25519 signature must be 64");
_Static_assert(JAR_BANDERSNATCH_PUBKEY_SIZE == 32, "Bandersnatch public key must be 32");
_Static_assert(JAR_BANDERSNATCH_SIG_SIZE == 96, "Bandersnatch signature must be 96");
_Static_assert(JAR_BANDERSNATCH_ROOT_SIZE == 144, "Bandersnatch ring root must be 144");
_Static_assert(JAR_BANDERSNATCH_RING_PROOF_SIZE == 784, "Bandersnatch ring proof must be 784");
_Static_assert(JAR_BLS_PUBKEY_SIZE == 144, "BLS public key must be 144");
_Static_assert(JAR_BLS_SIG_SIZE == 48, "BLS signature must be 48");

/* Rust FFI declarations */
extern void    jar_ffi_blake2b(const uint8_t* data, size_t len, uint8_t* out);
extern void    jar_ffi_keccak256(const uint8_t* data, size_t len, uint8_t* out);
extern uint8_t jar_ffi_ed25519_verify(const uint8_t* key, const uint8_t* msg, size_t msg_len, const uint8_t* sig);
extern void    jar_ffi_ed25519_sign(const uint8_t* secret, size_t secret_len, const uint8_t* msg, size_t msg_len, uint8_t* out);
extern uint8_t jar_ffi_bandersnatch_verify(const uint8_t* key, const uint8_t* ctx, size_t ctx_len, const uint8_t* msg, size_t msg_len, const uint8_t* sig);
extern void    jar_ffi_bandersnatch_sign(const uint8_t* secret, size_t secret_len, const uint8_t* ctx, size_t ctx_len, const uint8_t* msg, size_t msg_len, uint8_t* out);
extern uint8_t jar_ffi_bandersnatch_output(const uint8_t* sig, uint8_t* out);
extern void    jar_ffi_bandersnatch_ring_root(const uint8_t* keys, size_t num_keys, uint8_t* out);
extern uint8_t jar_ffi_bandersnatch_ring_verify(const uint8_t* root, const uint8_t* ctx, size_t ctx_len, const uint8_t* msg, size_t msg_len, const uint8_t* proof, size_t ring_size);
extern void    jar_ffi_bandersnatch_ring_sign(const uint8_t* secret, size_t secret_len, const uint8_t* root, const uint8_t* ctx, size_t ctx_len, const uint8_t* msg, size_t msg_len, size_t ring_size, uint8_t* out);
extern uint8_t jar_ffi_bandersnatch_ring_output(const uint8_t* proof, uint8_t* out);
extern uint8_t jar_ffi_bls_verify(const uint8_t* key, const uint8_t* msg, size_t msg_len, const uint8_t* sig);
extern void    jar_ffi_bls_sign(const uint8_t* secret, size_t secret_len, const uint8_t* msg, size_t msg_len, uint8_t* out);

/*
 * Helper: create an OctetSeq n from raw bytes.
 *
 * OctetSeq is { data : ByteArray, size_eq : Prop }. Since size_eq is a Prop,
 * it is erased at runtime. Lean compiles OctetSeq as just ByteArray.
 */
static lean_obj_res mk_octet_seq(const uint8_t* bytes, size_t n) {
    lean_object* ba = lean_alloc_sarray(1, n, n);
    memcpy(lean_sarray_cptr(ba), bytes, n);
    return ba;
}

/*
 * Helper: extract raw byte pointer from an OctetSeq.
 * At runtime OctetSeq IS the ByteArray (Prop field erased).
 */
static const uint8_t* octet_seq_data(b_lean_obj_arg seq) {
    return lean_sarray_cptr(seq);
}

/* ======================================================================== */
/* blake2b(m : ByteArray) : Hash                                            */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_blake2b(b_lean_obj_arg m) {
    uint8_t hash[JAR_HASH_SIZE];
    jar_ffi_blake2b(lean_sarray_cptr(m), lean_sarray_size(m), hash);
    return mk_octet_seq(hash, JAR_HASH_SIZE);
}

/* ======================================================================== */
/* keccak256(m : ByteArray) : Hash                                          */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_keccak256(b_lean_obj_arg m) {
    uint8_t hash[JAR_HASH_SIZE];
    jar_ffi_keccak256(lean_sarray_cptr(m), lean_sarray_size(m), hash);
    return mk_octet_seq(hash, JAR_HASH_SIZE);
}

/* ======================================================================== */
/* ed25519Verify(key : Ed25519PublicKey, message : ByteArray,               */
/*               sig : Ed25519Signature) : Bool                             */
/* ======================================================================== */
LEAN_EXPORT uint8_t jar_ed25519_verify(
    b_lean_obj_arg key, b_lean_obj_arg message, b_lean_obj_arg sig
) {
    uint8_t r = jar_ffi_ed25519_verify(
        octet_seq_data(key),
        lean_sarray_cptr(message), lean_sarray_size(message),
        octet_seq_data(sig)
    );
    return r ? 1 : 0;
}

/* ======================================================================== */
/* ed25519Sign(secretKey : ByteArray, message : ByteArray)                  */
/*   : Ed25519Signature                                                     */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_ed25519_sign(
    b_lean_obj_arg secretKey, b_lean_obj_arg message
) {
    uint8_t sig[JAR_ED25519_SIG_SIZE];
    jar_ffi_ed25519_sign(
        lean_sarray_cptr(secretKey), lean_sarray_size(secretKey),
        lean_sarray_cptr(message), lean_sarray_size(message),
        sig
    );
    return mk_octet_seq(sig, JAR_ED25519_SIG_SIZE);
}

/* ======================================================================== */
/* bandersnatchVerify(key : BandersnatchPublicKey, context : ByteArray,     */
/*                    message : ByteArray,                                   */
/*                    sig : BandersnatchSignature) : Bool                    */
/* ======================================================================== */
LEAN_EXPORT uint8_t jar_bandersnatch_verify(
    b_lean_obj_arg key, b_lean_obj_arg context,
    b_lean_obj_arg message, b_lean_obj_arg sig
) {
    uint8_t r = jar_ffi_bandersnatch_verify(
        octet_seq_data(key),
        lean_sarray_cptr(context), lean_sarray_size(context),
        lean_sarray_cptr(message), lean_sarray_size(message),
        octet_seq_data(sig)
    );
    return r ? 1 : 0;
}

/* ======================================================================== */
/* bandersnatchSign(secretKey : ByteArray, context : ByteArray,             */
/*                  message : ByteArray) : BandersnatchSignature             */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_bandersnatch_sign(
    b_lean_obj_arg secretKey, b_lean_obj_arg context, b_lean_obj_arg message
) {
    uint8_t sig[JAR_BANDERSNATCH_SIG_SIZE];
    jar_ffi_bandersnatch_sign(
        lean_sarray_cptr(secretKey), lean_sarray_size(secretKey),
        lean_sarray_cptr(context), lean_sarray_size(context),
        lean_sarray_cptr(message), lean_sarray_size(message),
        sig
    );
    return mk_octet_seq(sig, JAR_BANDERSNATCH_SIG_SIZE);
}

/* ======================================================================== */
/* bandersnatchOutput(sig : BandersnatchSignature) : Hash                   */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_bandersnatch_output(b_lean_obj_arg sig) {
    uint8_t hash[JAR_HASH_SIZE];
    /* Returns 1 on success, 0 on failure. On failure hash is zeroed. */
    jar_ffi_bandersnatch_output(octet_seq_data(sig), hash);
    return mk_octet_seq(hash, JAR_HASH_SIZE);
}

/* ======================================================================== */
/* bandersnatchRingRoot(keys : Array BandersnatchPublicKey)                  */
/*   : BandersnatchRingRoot                                                 */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_bandersnatch_ring_root(b_lean_obj_arg keys) {
    size_t n = lean_array_size(keys);
    uint8_t* buf = NULL;
    if (n > 0) {
        buf = (uint8_t*)malloc(n * JAR_BANDERSNATCH_PUBKEY_SIZE);
        for (size_t i = 0; i < n; i++) {
            lean_object* elem = lean_array_cptr(keys)[i];
            memcpy(buf + i * JAR_BANDERSNATCH_PUBKEY_SIZE, octet_seq_data(elem), JAR_BANDERSNATCH_PUBKEY_SIZE);
        }
    }
    uint8_t root[JAR_BANDERSNATCH_ROOT_SIZE];
    jar_ffi_bandersnatch_ring_root(buf, n, root);
    free(buf);
    return mk_octet_seq(root, JAR_BANDERSNATCH_ROOT_SIZE);
}

/* ======================================================================== */
/* bandersnatchRingVerify(root : BandersnatchRingRoot,                      */
/*   context : ByteArray, message : ByteArray,                              */
/*   proof : BandersnatchRingVrfProof) : Bool                               */
/* ======================================================================== */
LEAN_EXPORT uint8_t jar_bandersnatch_ring_verify(
    b_lean_obj_arg root, b_lean_obj_arg context,
    b_lean_obj_arg message, b_lean_obj_arg proof,
    uint32_t ringSize
) {
    size_t ring_size = (size_t)ringSize;
    uint8_t r = jar_ffi_bandersnatch_ring_verify(
        octet_seq_data(root),
        lean_sarray_cptr(context), lean_sarray_size(context),
        lean_sarray_cptr(message), lean_sarray_size(message),
        octet_seq_data(proof),
        ring_size
    );
    return r ? 1 : 0;
}

/* ======================================================================== */
/* bandersnatchRingSign(secretKey : ByteArray,                              */
/*   root : BandersnatchRingRoot, context : ByteArray,                      */
/*   message : ByteArray) : BandersnatchRingVrfProof                        */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_bandersnatch_ring_sign(
    b_lean_obj_arg secretKey, b_lean_obj_arg root,
    b_lean_obj_arg context, b_lean_obj_arg message,
    uint32_t ringSize
) {
    size_t ring_size = (size_t)ringSize;
    uint8_t proof[JAR_BANDERSNATCH_RING_PROOF_SIZE];
    jar_ffi_bandersnatch_ring_sign(
        lean_sarray_cptr(secretKey), lean_sarray_size(secretKey),
        octet_seq_data(root),
        lean_sarray_cptr(context), lean_sarray_size(context),
        lean_sarray_cptr(message), lean_sarray_size(message),
        ring_size,
        proof
    );
    return mk_octet_seq(proof, JAR_BANDERSNATCH_RING_PROOF_SIZE);
}

/* ======================================================================== */
/* bandersnatchRingOutput(proof : BandersnatchRingVrfProof) : Hash          */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_bandersnatch_ring_output(b_lean_obj_arg proof) {
    uint8_t hash[JAR_HASH_SIZE];
    jar_ffi_bandersnatch_ring_output(octet_seq_data(proof), hash);
    return mk_octet_seq(hash, JAR_HASH_SIZE);
}

/* ======================================================================== */
/* blsVerify(key : BlsPublicKey, message : ByteArray,                       */
/*           sig : BlsSignature) : Bool                                     */
/* ======================================================================== */
LEAN_EXPORT uint8_t jar_bls_verify(
    b_lean_obj_arg key, b_lean_obj_arg message, b_lean_obj_arg sig
) {
    uint8_t r = jar_ffi_bls_verify(
        octet_seq_data(key),
        lean_sarray_cptr(message), lean_sarray_size(message),
        octet_seq_data(sig)
    );
    return r ? 1 : 0;
}

/* ======================================================================== */
/* blsSign(secretKey : ByteArray, message : ByteArray) : BlsSignature       */
/* ======================================================================== */
LEAN_EXPORT lean_obj_res jar_bls_sign(
    b_lean_obj_arg secretKey, b_lean_obj_arg message
) {
    uint8_t sig[JAR_BLS_SIG_SIZE];
    memset(sig, 0, JAR_BLS_SIG_SIZE);
    jar_ffi_bls_sign(
        lean_sarray_cptr(secretKey), lean_sarray_size(secretKey),
        lean_sarray_cptr(message), lean_sarray_size(message),
        sig
    );
    return mk_octet_seq(sig, JAR_BLS_SIG_SIZE);
}
