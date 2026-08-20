#ifndef PQCLEAN_RANDOMBYTES_H
#define PQCLEAN_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

/**
 * Random bytes provider for the vendored FIPS 203/204 reference
 * implementations. Implemented in libraries/fc/src/crypto/pqc.cpp on top of
 * fc::rand_bytes(). When a deterministic seed has been installed via
 * pq_random_set_deterministic_seed(), all draws are derived from that seed
 * with SHAKE-256 so that ML-DSA/ML-KEM keypairs become reproducible
 * (required for deterministic re-derivation of wallet keys, Approach A in
 * docs/Post-Quantum-Migration.md).
 */
void randombytes(uint8_t *out, size_t n);

#endif