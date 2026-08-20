#include <fc/crypto/pqc.hpp>

#include <fc/crypto/base58.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/exception/exception.hpp>

#include <cstring>
#include <limits>

/* Vendored FIPS-202 SHA-3/SHAKE permutation used by the FIPS 203/204
   reference implementations (compiled as C, so declare extern "C"). */
extern "C" {
#include "fips202.h"
}

/**
 * Deterministic randomness scope.
 *
 * FIPS 204 §4.2.1 / FIPS 203 §4 define key generation as deterministic
 * functions of a seed, and the reference implementations read that seed
 * through `randombytes()`. While a deterministic scope is active we answer
 * every randombytes() draw from SHAKE-256 expanded from the caller-supplied
 * seed, yielding reproducible keypairs without modifying vendor code.
 */
namespace
{
struct deterministic_scope
{
   bool       active = false;
   fc::sha256 seed;
   uint64_t   counter = 0;

   void fill( uint8_t* out, size_t n )
   {
      constexpr size_t CHUNK = 64;
      std::array<uint8_t, 32 + 8> st;
      memcpy( st.data(), seed.data(), 32 );
      while( n > 0 )
      {
         uint64_t c = counter++;
         for( int i = 0; i < 8; ++i )
            st[32 + i] = (uint8_t)( c >> (8 * i) );
         size_t take = n < CHUNK ? n : CHUNK;
         shake256( out, take, st.data(), st.size() );
         out += take;
         n   -= take;
      }
   }
};

thread_local deterministic_scope g_det_scope;

struct det_guard
{
   explicit det_guard( const fc::sha256& seed )
      : prev( g_det_scope )
   {
      g_det_scope = deterministic_scope{ true, seed, 0 };
   }
   ~det_guard() { g_det_scope = prev; }
   deterministic_scope prev;
};
} // anonymous namespace

/* Randomness provider for the vendored code; overrideable by the
 * deterministic scope above. */
extern "C" void randombytes( uint8_t* out, size_t n )
{
   if( g_det_scope.active )
      g_det_scope.fill( out, n );
   else
   {
      FC_ASSERT( n <= static_cast<size_t>(std::numeric_limits<int>::max()),
                 "randombytes requested too many bytes" );
      fc::rand_bytes( reinterpret_cast<char*>( out ), static_cast<int>(n) );
   }
}

using namespace fc;

/* --------------------- vendored PQClean C symbols ------------------------ */

#define PQC_DECLARE_MLDSA(M) \
   int PQCLEAN_MLDSA##M##_CLEAN_crypto_sign_keypair(uint8_t*, uint8_t*); \
   int PQCLEAN_MLDSA##M##_CLEAN_crypto_sign_signature(uint8_t*, size_t*, \
         const uint8_t*, size_t, const uint8_t*); \
   int PQCLEAN_MLDSA##M##_CLEAN_crypto_sign_verify(const uint8_t*, size_t, \
         const uint8_t*, size_t, const uint8_t*)

#define PQC_DECLARE_MLKEM(M) \
   int PQCLEAN_MLKEM##M##_CLEAN_crypto_kem_keypair(uint8_t*, uint8_t*); \
   int PQCLEAN_MLKEM##M##_CLEAN_crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk); \
   int PQCLEAN_MLKEM##M##_CLEAN_crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)

#ifdef __cplusplus
extern "C" {
#endif
PQC_DECLARE_MLDSA(44);
PQC_DECLARE_MLDSA(65);
PQC_DECLARE_MLDSA(87);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
PQC_DECLARE_MLKEM(512);
PQC_DECLARE_MLKEM(768);
PQC_DECLARE_MLKEM(1024);
#ifdef __cplusplus
}
#endif

namespace {

struct sig_impl
{
   int (*keypair)( uint8_t*, uint8_t* );
   int (*sign)( uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t* );
   int (*verify)( const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t* );
   uint16_t pk_size, sk_size, sig_size;
};

struct kem_impl
{
   int (*keypair)( uint8_t*, uint8_t* );
   int (*enc)( uint8_t* ct, uint8_t* ss, const uint8_t* pk );
   int (*dec)( uint8_t* ss, const uint8_t* ct, const uint8_t* sk );
   uint16_t pk_size, sk_size, ct_size, ss_size;
};

const sig_impl& get_sig( pq_algorithm a )
{
   static const sig_impl s44 = { PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
                                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature,
                                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify,
                                 1312, 2560, 2420 };
   static const sig_impl s65 = { PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
                                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature,
                                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify,
                                 1952, 4032, 3309 };
   static const sig_impl s87 = { PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
                                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature,
                                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify,
                                 2592, 4896, 4627 };
   switch( a )
   {
      case pq_algorithm::ml_dsa_44: return s44;
      case pq_algorithm::ml_dsa_65: return s65;
      case pq_algorithm::ml_dsa_87: return s87;
      default:
         FC_THROW_EXCEPTION( invalid_arg_exception,
                             "pq_algorithm ${a} is not an ML-DSA parameter set",
                             ("a", (uint8_t)a) );
   }
}

const kem_impl& get_kem( pq_algorithm a )
{
   static const kem_impl k512 =  { PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
                                   PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
                                   PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec,
                                   800, 1632, 768, 32 };
   static const kem_impl k768 =  { PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
                                   PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
                                   PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec,
                                   1184, 2400, 1088, 32 };
   static const kem_impl k1024 = { PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
                                   PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
                                   PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec,
                                   1568, 3168, 1568, 32 };
   switch( a )
   {
      case pq_algorithm::ml_kem_512:  return k512;
      case pq_algorithm::ml_kem_768:  return k768;
      case pq_algorithm::ml_kem_1024: return k1024;
      default:
         FC_THROW_EXCEPTION( invalid_arg_exception,
                             "pq_algorithm ${a} is not an ML-KEM parameter set",
                             ("a", (uint8_t)a) );
   }
}

std::vector<char> to_vec( const uint8_t* p, size_t n )
{
   return std::vector<char>( p, p + n );
}

} // anonymous namespace

namespace fc {

/* --------------------------------- sizes --------------------------------- */

uint16_t pqc_sizes::public_key_size( pq_algorithm a )
{
   switch( a )
   {
      case pq_algorithm::ml_dsa_44:   return 1312;
      case pq_algorithm::ml_dsa_65:   return 1952;
      case pq_algorithm::ml_dsa_87:   return 2592;
      case pq_algorithm::ml_kem_512:  return 800;
      case pq_algorithm::ml_kem_768:  return 1184;
      case pq_algorithm::ml_kem_1024: return 1568;
      default: return 0;
   }
}

uint16_t pqc_sizes::private_key_size( pq_algorithm a )
{
   switch( a )
   {
      case pq_algorithm::ml_dsa_44:   return 2560;
      case pq_algorithm::ml_dsa_65:   return 4032;
      case pq_algorithm::ml_dsa_87:   return 4896;
      case pq_algorithm::ml_kem_512:  return 1632;
      case pq_algorithm::ml_kem_768:  return 2400;
      case pq_algorithm::ml_kem_1024: return 3168;
      default: return 0;
   }
}

uint16_t pqc_sizes::signature_size( pq_algorithm a )
{
   switch( a )
   {
      case pq_algorithm::ml_dsa_44: return 2420;
      case pq_algorithm::ml_dsa_65: return 3309;
      case pq_algorithm::ml_dsa_87: return 4627;
      default: return 0;
   }
}

uint16_t pqc_sizes::ciphertext_size( pq_algorithm a )
{
   switch( a )
   {
      case pq_algorithm::ml_kem_512:  return 768;
      case pq_algorithm::ml_kem_768:  return 1088;
      case pq_algorithm::ml_kem_1024: return 1568;
      default: return 0;
   }
}

uint16_t pqc_sizes::shared_secret_size( pq_algorithm )
{
   return 32;
}

/* -------------------------------- ML-DSA --------------------------------- */

pq_public_key::pq_public_key( pq_algorithm alg, std::vector<char> key )
   : alg_( (uint8_t)alg ), key_( std::move( key ) )
{
   FC_ASSERT( alg_ != 0, "pq_public_key must specify an algorithm" );
   FC_ASSERT( key_.size() == pqc_sizes::public_key_size( (pq_algorithm)alg_ ),
              "pq public key length ${len} does not match algorithm ${a}",
              ("len", key_.size())("a", alg_) );
}

pq_private_key::pq_private_key( pq_algorithm alg, std::vector<char> sk,
                                std::vector<char> pk )
   : alg_( (uint8_t)alg ), key_( std::move( sk ) ), pub_( std::move( pk ) )
{
   FC_ASSERT( alg_ != 0, "pq_private_key must specify an algorithm" );
   FC_ASSERT( key_.size() == pqc_sizes::private_key_size( (pq_algorithm)alg_ ),
              "pq private key length ${len} does not match algorithm ${a}",
              ("len", key_.size())("a", alg_) );
   FC_ASSERT( pub_.size() == pqc_sizes::public_key_size( (pq_algorithm)alg_ ),
              "pq public key length ${len} does not match algorithm ${a}",
              ("len", pub_.size())("a", alg_) );
}

pq_private_key pq_private_key::generate( pq_algorithm alg )
{
   const sig_impl& impl = get_sig( alg );
   std::vector<char> sk( impl.sk_size ), pk( impl.pk_size );
   int rc = impl.keypair( (uint8_t*)pk.data(), (uint8_t*)sk.data() );
   if( rc != 0 )
      FC_THROW_EXCEPTION( assert_exception, "ML-DSA key generation failed (rc=${rc})", ("rc", rc) );
   return pq_private_key( alg, std::move( sk ), std::move( pk ) );
}

pq_private_key pq_private_key::regenerate_from_seed( pq_algorithm alg,
                                                     const fc::sha256& seed )
{
   det_guard guard( seed );
   return pq_private_key::generate( alg );
}

pq_private_key pq_private_key::regenerate( const fc::sha256& seed )
{
   return regenerate_from_seed( pq_algorithm::ml_dsa_65, seed );
}

pq_public_key pq_private_key::get_public_key() const
{
   return pq_public_key( algorithm(), pub_ );
}

std::vector<char> pq_private_key::sign( const fc::sha256& digest ) const
{
   FC_ASSERT( valid(), "cannot sign with an empty pq key" );
   const sig_impl& impl = get_sig( algorithm() );
   std::vector<char> sig( impl.sig_size );
   size_t siglen = 0;
   int rc = impl.sign( (uint8_t*)sig.data(), &siglen,
                       (const uint8_t*)digest.data(), digest.data_size(),
                       (const uint8_t*)key_.data() );
   if( rc != 0 )
      FC_THROW_EXCEPTION( assert_exception, "ML-DSA signing failed (rc=${rc})", ("rc", rc) );
   sig.resize( siglen );
   return sig;
}

bool pq_public_key::verify( const fc::sha256& digest, const std::vector<char>& sig ) const
{
   try
   {
      if( !valid() ) return false;
      const sig_impl& impl = get_sig( algorithm() );
      return impl.verify( (const uint8_t*)sig.data(), sig.size(),
                          (const uint8_t*)digest.data(), digest.data_size(),
                          (const uint8_t*)key_.data() ) == 0;
   }
   catch( const fc::exception& )
   {
      return false;
   }
}

/* ------------------------------- keypairs -------------------------------- */

pq_keypair pq_generate_keypair( pq_algorithm alg )
{
   pq_keypair r;
   r.priv = pq_private_key::generate( alg );
   r.pub  = r.priv.get_public_key();
   return r;
}

pq_keypair pq_generate_keypair_from_seed( pq_algorithm alg, const fc::sha256& seed )
{
   pq_keypair r;
   r.priv = pq_private_key::regenerate_from_seed( alg, seed );
   r.pub  = r.priv.get_public_key();
   return r;
}

/* -------------------------------- ML-KEM --------------------------------- */

pq_kem_keypair pq_kem_generate( pq_algorithm alg )
{
   const kem_impl& impl = get_kem( alg );
   pq_kem_keypair k;
   k.pk.resize( impl.pk_size );
   k.sk.resize( impl.sk_size );
   if( impl.keypair( (uint8_t*)k.pk.data(), (uint8_t*)k.sk.data() ) != 0 )
      FC_THROW_EXCEPTION( assert_exception, "ML-KEM key generation failed" );
   return k;
}

pq_kem_result pq_kem_encapsulate( pq_algorithm alg, const std::vector<char>& pk )
{
   const kem_impl& impl = get_kem( alg );
   FC_ASSERT( pk.size() == impl.pk_size, "ML-KEM public key length mismatch" );
   pq_kem_result r;
   r.ciphertext.resize( impl.ct_size );
   r.shared_secret.resize( impl.ss_size );
   if( impl.enc( (uint8_t*)r.ciphertext.data(), (uint8_t*)r.shared_secret.data(),
                 (const uint8_t*)pk.data() ) != 0 )
      return r;
   r.valid = true;
   return r;
}

std::vector<char> pq_kem_decapsulate( pq_algorithm alg, const std::vector<char>& sk,
                                      const std::vector<char>& ct )
{
   const kem_impl& impl = get_kem( alg );
   FC_ASSERT( sk.size() == impl.sk_size, "ML-KEM private key length mismatch" );
   FC_ASSERT( ct.size() == impl.ct_size, "ML-KEM ciphertext length mismatch" );
   std::vector<char> ss( impl.ss_size );
   if( impl.dec( (uint8_t*)ss.data(), (const uint8_t*)ct.data(),
                 (const uint8_t*)sk.data() ) != 0 )
      FC_THROW_EXCEPTION( assert_exception, "ML-KEM decapsulation failed" );
   return ss;
}

/* ------------------------- base58 & variants ----------------------------- */

std::string pq_public_key::to_base58() const
{
   std::vector<char> payload;
   payload.reserve( key_.size() + 1 );
   payload.push_back( (char)alg_ );
   payload.insert( payload.end(), key_.begin(), key_.end() );
   return fc::to_base58( payload );
}

pq_public_key pq_public_key::from_base58( const std::string& b58 )
{
   auto payload = fc::from_base58( b58 );
   FC_ASSERT( payload.size() > 1, "invalid pq_public_key base58" );
   auto alg = (pq_algorithm)(uint8_t)payload[0];
   std::vector<char> key( payload.begin() + 1, payload.end() );
   return pq_public_key( alg, std::move( key ) );
}

std::string pq_private_key::to_base58() const
{
   std::vector<char> payload;
   payload.reserve( key_.size() + pub_.size() + 1 );
   payload.push_back( (char)alg_ );
   payload.insert( payload.end(), key_.begin(), key_.end() );
   payload.insert( payload.end(), pub_.begin(), pub_.end() );
   return fc::to_base58( payload );
}

pq_private_key pq_private_key::from_base58( const std::string& b58 )
{
   auto payload = fc::from_base58( b58 );
   FC_ASSERT( payload.size() > 1, "invalid pq_private_key base58" );
   auto alg = (pq_algorithm)(uint8_t)payload[0];
   uint16_t sk_size = pqc_sizes::private_key_size( alg );
   uint16_t pk_size = pqc_sizes::public_key_size( alg );
   FC_ASSERT( payload.size() == size_t( 1 ) + sk_size + pk_size,
              "unexpected pq_private_key length" );
   pq_private_key k;
   k.alg_ = (uint8_t)payload[0];
   k.key_.assign( payload.begin() + 1, payload.begin() + 1 + sk_size );
   k.pub_.assign( payload.begin() + 1 + sk_size, payload.end() );
   return k;
}

} // namespace fc