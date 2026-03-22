/*
 * Shared buffer size constants for JAR crypto FFI.
 *
 * These must match the OctetSeq N types in Jar/Crypto.lean.
 * Both bridge.c and lib.rs use these values; any mismatch
 * between C buffers and Lean types causes silent memory corruption.
 */

#ifndef JAR_CRYPTO_SIZES_H
#define JAR_CRYPTO_SIZES_H

#define JAR_HASH_SIZE                    32   /* Hash = OctetSeq 32 */
#define JAR_ED25519_PUBKEY_SIZE          32   /* Ed25519PublicKey = OctetSeq 32 */
#define JAR_ED25519_SIG_SIZE             64   /* Ed25519Signature = OctetSeq 64 */
#define JAR_BANDERSNATCH_PUBKEY_SIZE     32   /* BandersnatchPublicKey = OctetSeq 32 */
#define JAR_BANDERSNATCH_SIG_SIZE        96   /* BandersnatchSignature = OctetSeq 96 */
#define JAR_BANDERSNATCH_ROOT_SIZE      144   /* BandersnatchRingRoot = OctetSeq 144 */
#define JAR_BANDERSNATCH_RING_PROOF_SIZE 784  /* BandersnatchRingVrfProof = OctetSeq 784 */
#define JAR_BLS_PUBKEY_SIZE             144   /* BlsPublicKey = OctetSeq 144 */
#define JAR_BLS_SIG_SIZE                 48   /* BlsSignature = OctetSeq 48 */

#endif
