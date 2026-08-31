/*
 * What post-quantum signatures cost a node, measured rather than estimated.
 *
 * Consensus spends its signature budget in one place: every node verifies every signature in
 * every block, so verification throughput is what decides whether a block validates inside
 * its slot. secp256k1 does not verify at all in Graphene -- it *recovers* the public key from
 * the signature, which is why a classical transaction carries 65 bytes and no key. ML-DSA has
 * no recovery, so a PQ transaction carries the key (1952 bytes) as well as the signature
 * (3309), and the node verifies instead of recovering.
 *
 * The numbers this prints are the inputs to two decisions: what `maximum_block_size` can hold,
 * and whether a full block of PQ transactions still validates in a 3-second slot.
 *
 * Deliberately single-threaded. Graphene precomputes signatures in parallel
 * (database::precompute_parallel), so a real node does better than this on a multi-core
 * machine -- but the per-core cost is what scales, and a worst case that fits is a claim that
 * holds regardless of how many cores a validator brings.
 *
 * RUN THIS AGAINST AN OPTIMIZED BUILD. secp256k1 arrives as an already-optimized library
 * while the vendored PQClean is built with the project, so a Debug build handicaps only one
 * side of the comparison: measured here, -O0 put ML-DSA verification at 571 us and the ratio
 * at 6.5x, against 224 us and 2.6x at -O2. The unoptimized numbers are not merely pessimistic,
 * they are pessimistic about the wrong thing. Either build Release, or at minimum:
 *
 *     cmake -DCMAKE_C_FLAGS_DEBUG='-g -O2' . && make pqclean pqc_load_test
 */
#include <fc/crypto/pqc.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/time.hpp>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace {

/// Seconds per block on BitShares. A block that takes longer than this to validate cannot
/// keep up with the chain, never mind leave room for anything else.
constexpr double BLOCK_INTERVAL_S = 3.0;

/// Wire sizes, from the FIPS parameter sets and Graphene's own serialization.
constexpr size_t ECC_SIG_BYTES = 65;     // compact signature, key is recovered from it
constexpr size_t PQ_SIG_BYTES  = 3309;   // ML-DSA-65 signature
constexpr size_t PQ_KEY_BYTES  = 1952;   // ML-DSA-65 public key, carried with the signature

struct timing
{
   double per_op_us;
   double per_second;
};

template<typename F>
timing measure( const char* what, int iterations, F&& f )
{
   // One untimed pass so first-touch page faults and lazy initialization do not land in the
   // measurement.
   f( 0 );

   const auto start = fc::time_point::now();
   for( int i = 0; i < iterations; ++i )
      f( i );
   const auto elapsed = fc::time_point::now() - start;

   const double total_us = double( elapsed.count() );
   timing t{ total_us / iterations, iterations * 1000000.0 / total_us };
   std::printf( "  %-34s %9.1f us/op   %10.0f ops/s\n", what, t.per_op_us, t.per_second );
   return t;
}

} // namespace

int main()
{
   std::printf( "Post-quantum signature load, single core\n" );
   std::printf( "=======================================\n\n" );

   const fc::sha256 digest = fc::sha256::hash( std::string( "load measurement" ) );

   /* ------------------------------- classical baseline ------------------------------- */

   std::printf( "secp256k1 (what the chain does today)\n" );
   const fc::ecc::private_key ecc_priv = fc::ecc::private_key::generate();
   const fc::ecc::compact_signature ecc_sig = ecc_priv.sign_compact( digest );

   const auto ecc_sign = measure( "sign", 2000, [&]( int ) {
      volatile auto s = ecc_priv.sign_compact( digest );
      (void)s;
   } );
   const auto ecc_recover = measure( "recover (this is verification)", 2000, [&]( int ) {
      volatile auto k = fc::ecc::public_key( ecc_sig, digest );
      (void)k;
   } );
   (void)ecc_sign;

   /* ---------------------------------- ML-DSA-65 ------------------------------------- */

   std::printf( "\nML-DSA-65 (FIPS 204)\n" );
   const fc::pq_private_key pq_priv = fc::pq_private_key::generate( fc::pq_algorithm::ml_dsa_65 );
   const fc::pq_public_key  pq_pub  = pq_priv.get_public_key();
   const std::vector<char>  pq_sig  = pq_priv.sign( digest );

   measure( "keygen", 200, [&]( int ) {
      volatile auto k = fc::pq_private_key::generate( fc::pq_algorithm::ml_dsa_65 );
      (void)k;
   } );
   measure( "sign", 200, [&]( int ) {
      volatile auto s = pq_priv.sign( digest );
      (void)s;
   } );
   const auto pq_verify = measure( "verify", 500, [&]( int ) {
      volatile bool ok = pq_pub.verify( digest, pq_sig );
      (void)ok;
   } );

   /* ------------------------------- what that means ---------------------------------- */

   const double slowdown = pq_verify.per_op_us / ecc_recover.per_op_us;
   std::printf( "\nVerification is %.1fx the cost of a secp256k1 recovery.\n", slowdown );

   std::printf( "\nSignatures one core can check inside a %.0fs block slot\n", BLOCK_INTERVAL_S );
   const double ecc_per_slot = ecc_recover.per_second * BLOCK_INTERVAL_S;
   const double pq_per_slot  = pq_verify.per_second  * BLOCK_INTERVAL_S;
   std::printf( "  secp256k1 %10.0f\n", ecc_per_slot );
   std::printf( "  ML-DSA-65 %10.0f\n", pq_per_slot );

   std::printf( "\nWire cost per signed transaction\n" );
   std::printf( "  secp256k1 %5zu bytes (signature only; the key is recovered)\n", ECC_SIG_BYTES );
   std::printf( "  ML-DSA-65 %5zu bytes (signature %zu + embedded key %zu)\n",
                PQ_SIG_BYTES + PQ_KEY_BYTES, PQ_SIG_BYTES, PQ_KEY_BYTES );
   std::printf( "  ratio     %5.1fx\n", double( PQ_SIG_BYTES + PQ_KEY_BYTES ) / ECC_SIG_BYTES );

   std::printf( "\nBlock occupancy at BitShares' 2 MB maximum_block_size\n" );
   const size_t block_bytes = 2u * 1024u * 1024u;
   // A minimal transfer body is about 80 bytes on top of its signature material.
   const size_t body = 80;
   const size_t ecc_tx = block_bytes / ( body + ECC_SIG_BYTES );
   const size_t pq_tx  = block_bytes / ( body + PQ_SIG_BYTES + PQ_KEY_BYTES );
   std::printf( "  transfers per block, secp256k1 %6zu\n", ecc_tx );
   std::printf( "  transfers per block, ML-DSA-65 %6zu\n", pq_tx );
   std::printf( "  a full PQ block needs %.2fs of one core to verify\n",
                pq_tx * pq_verify.per_op_us / 1000000.0 );

   std::printf( "\nSustained bandwidth if every block were full\n" );
   std::printf( "  secp256k1 %6.1f GB/day\n",
                block_bytes * ( 86400.0 / BLOCK_INTERVAL_S ) / 1e9 );
   std::printf( "  (block size caps bandwidth either way; what changes is how much\n"
                "   useful work fits inside it -- %.1fx fewer transfers)\n",
                double( ecc_tx ) / double( pq_tx ) );

   const bool slot_ok = pq_tx * pq_verify.per_op_us / 1000000.0 < BLOCK_INTERVAL_S;
   std::printf( "\n%s\n", slot_ok
      ? "A full post-quantum block validates inside its slot on a single core."
      : "WARNING: a full post-quantum block does NOT validate inside its slot on one core." );
   return 0;
}
