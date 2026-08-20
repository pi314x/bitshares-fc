#pragma once
/**
 * Post-quantum cryptography primitives for fc, following the NIST
 * FIPS-approved standards:
 *
 *   - FIPS 204 (ML-DSA): signature scheme (Dilithium)
 *   - FIPS 203 (ML-KEM): key encapsulation mechanism (Kyber)
 *
 * Backends are the audited PQClean reference implementations vendored in
 * libraries/fc/vendor/pqclean. See docs/Post-Quantum-Migration.md.
 */
#include <fc/io/raw_fwd.hpp>
#include <fc/variant.hpp>
#include <fc/crypto/sha256.hpp>

#include <vector>

namespace fc {

enum class pq_algorithm : uint8_t
{
   none        = 0,
   ml_dsa_44   = 1, ///< FIPS 204, NIST strength Category 2
   ml_dsa_65   = 2, ///< FIPS 204, NIST strength Category 3 (default)
   ml_dsa_87   = 3, ///< FIPS 204, NIST strength Category 5
   ml_kem_512  = 4, ///< FIPS 203, NIST strength Category 1
   ml_kem_768  = 5, ///< FIPS 203, NIST strength Category 3 (default KEM)
   ml_kem_1024 = 6  ///< FIPS 203, NIST strength Category 5
};

/// Byte sizes of the FIPS 203/204 parameter sets (0 for N/A).
struct pqc_sizes
{
   static uint16_t public_key_size(   pq_algorithm a );
   static uint16_t private_key_size(  pq_algorithm a );
   static uint16_t signature_size(    pq_algorithm a );
   static uint16_t ciphertext_size(   pq_algorithm a );
   static uint16_t shared_secret_size(pq_algorithm a );
};

/**
 * ML-DSA public key (FIPS 204). Self-describing: algorithm tag + raw
 * public key bytes (1312 / 1952 / 2592).
 */
class pq_public_key
{
   public:
      pq_public_key() = default;
      pq_public_key( pq_algorithm alg, std::vector<char> key );

      pq_algorithm algorithm() const { return (pq_algorithm)alg_; }
      const std::vector<char>& data() const { return key_; }

      bool valid() const { return alg_ != 0 && !key_.empty(); }

      /// Expected raw public-key length for an algorithm (0 if N/A).
      static uint16_t size_for_algorithm( pq_algorithm alg )
      { return pqc_sizes::public_key_size( alg ); }

      /** Verify an ML-DSA signature over a 32-byte digest (ctx=""). */
      bool verify( const fc::sha256& digest, const std::vector<char>& sig ) const;

      std::string to_base58() const;
      static pq_public_key from_base58( const std::string& b58 );

      friend bool operator==( const pq_public_key& a, const pq_public_key& b )
      { return a.alg_ == b.alg_ && a.key_ == b.key_; }
      friend bool operator!=( const pq_public_key& a, const pq_public_key& b ) { return !(a==b); }
      friend bool operator<( const pq_public_key& a, const pq_public_key& b )
      {
         if( a.alg_ != b.alg_ ) return a.alg_ < b.alg_;
         return a.key_ < b.key_;
      }

      uint8_t alg_ = 0;
      std::vector<char> key_;
};

/**
 * ML-DSA private key (FIPS 204). Holds the full secret key plus the
 * matching public key (like real-world key files do); key generation is
 * deterministic given a 32-byte seed (FIPS 204 §4.2.1), which lets a
 * wallet re-derive PQ keys from existing brain-key / WIF entropy.
 */
class pq_private_key
{
   public:
      pq_private_key() = default;
      pq_private_key( pq_algorithm alg, std::vector<char> sk,
                      std::vector<char> pk );

      /// Generate a fresh key with the given algorithm.
      static pq_private_key generate( pq_algorithm alg = pq_algorithm::ml_dsa_65 );

      /// Deterministic keygen from a 32-byte seed (Approach A re-derivation).
      static pq_private_key regenerate_from_seed( pq_algorithm alg,
                                                  const fc::sha256& seed );
      static pq_private_key regenerate( const fc::sha256& seed ); ///< ml_dsa_65

      pq_algorithm algorithm() const { return (pq_algorithm)alg_; }
      bool valid() const { return alg_ != 0 && !key_.empty(); }

      pq_public_key get_public_key() const;

      /** Deterministic ML-DSA signature over a 32-byte digest. */
      std::vector<char> sign( const fc::sha256& digest ) const;

      std::string to_base58() const;
      static pq_private_key from_base58( const std::string& b58 );

      uint8_t alg_ = 0;
      std::vector<char> key_; ///< private key bytes
      std::vector<char> pub_; ///< matching public key bytes

      friend bool operator==( const pq_private_key& a, const pq_private_key& b )
      { return a.alg_ == b.alg_ && a.key_ == b.key_ && a.pub_ == b.pub_; }
      friend bool operator!=( const pq_private_key& a, const pq_private_key& b ) { return !(a==b); }

   private:
      friend struct pq_keypair;
};

/** Convenience: generates an ML-DSA keypair. */
struct pq_keypair
{
   pq_public_key  pub;
   pq_private_key priv;
   bool valid() const { return pub.valid() && priv.valid(); }
};

pq_keypair pq_generate_keypair( pq_algorithm alg = pq_algorithm::ml_dsa_65 );
pq_keypair pq_generate_keypair_from_seed( pq_algorithm alg,
                                          const fc::sha256& seed );

/** ML-KEM (FIPS 203). */
struct pq_kem_keypair
{
   std::vector<char> pk, sk;
   bool valid() const { return !pk.empty() && !sk.empty(); }
};
struct pq_kem_result
{
   bool valid = false;
   std::vector<char> ciphertext;   ///< ct bytes (768/1088/1568)
   std::vector<char> shared_secret; ///< 32-byte session key
};

pq_kem_keypair pq_kem_generate( pq_algorithm alg = pq_algorithm::ml_kem_768 );
pq_kem_result  pq_kem_encapsulate( pq_algorithm alg, const std::vector<char>& pk );
std::vector<char> pq_kem_decapsulate( pq_algorithm alg,
                                      const std::vector<char>& sk,
                                      const std::vector<char>& ct );

namespace raw {
   template<typename Stream>
   inline void pack( Stream& s, const pq_public_key& pk, uint32_t _max_depth = FC_PACK_MAX_DEPTH )
   {
      FC_ASSERT( _max_depth > 0 );
      raw::pack( s, pk.alg_, _max_depth - 1 );
      raw::pack( s, pk.key_, _max_depth - 1 );
   }
   template<typename Stream>
   inline void unpack( Stream& s, pq_public_key& pk, uint32_t _max_depth = FC_PACK_MAX_DEPTH )
   {
      FC_ASSERT( _max_depth > 0 );
      raw::unpack( s, pk.alg_, _max_depth - 1 );
      raw::unpack( s, pk.key_, _max_depth - 1 );
   }
   template<typename Stream>
   inline void pack( Stream& s, const pq_private_key& k, uint32_t _max_depth = FC_PACK_MAX_DEPTH )
   {
      FC_ASSERT( _max_depth > 0 );
      raw::pack( s, k.alg_, _max_depth - 1 );
      raw::pack( s, k.key_, _max_depth - 1 );
      raw::pack( s, k.pub_, _max_depth - 1 );
   }
   template<typename Stream>
   inline void unpack( Stream& s, pq_private_key& k, uint32_t _max_depth = FC_PACK_MAX_DEPTH )
   {
      FC_ASSERT( _max_depth > 0 );
      raw::unpack( s, k.alg_, _max_depth - 1 );
      raw::unpack( s, k.key_, _max_depth - 1 );
      raw::unpack( s, k.pub_, _max_depth - 1 );
   }
} // namespace raw

} // namespace fc

#include <fc/reflect/reflect.hpp>
FC_REFLECT_ENUM( fc::pq_algorithm, (none)(ml_dsa_44)(ml_dsa_65)(ml_dsa_87)
                                      (ml_kem_512)(ml_kem_768)(ml_kem_1024) )
FC_REFLECT( fc::pq_public_key,  (alg_)(key_) )
FC_REFLECT( fc::pq_private_key, (alg_)(key_)(pub_) )