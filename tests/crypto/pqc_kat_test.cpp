/*
 * FIPS 203 / FIPS 204 conformance, against NIST's own answers.
 *
 * The rest of the post-quantum tests check that this code is self-consistent: what it
 * encrypts it decrypts, what it signs it verifies. That is necessary but nowhere near
 * sufficient -- a self-consistent implementation of the *wrong* algorithm passes every one of
 * them, and so does an implementation that is subtly off in a way both halves share. These
 * vectors come from NIST's ACVP test suite, so the expected outputs are not ours to choose.
 *
 * See pqc_kat/SOURCE.md for provenance and for what is deliberately not covered.
 *
 * Note on style: this deliberately does not use assert(). fc's tests are built in Release
 * configurations where NDEBUG makes assert() a no-op, which would turn a conformance failure
 * into a silent pass -- the exact failure mode this file exists to prevent.
 */

#include <fc/crypto/hex.hpp>
#include <fc/crypto/pqc.hpp>
#include <fc/io/json.hpp>
#include <fc/variant_object.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#ifndef FC_PQC_KAT_DIR
#error "FC_PQC_KAT_DIR must be defined by the build (see tests/CMakeLists.txt)"
#endif

extern "C" {
   int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand( uint8_t* pk, uint8_t* sk,
                                                         const uint8_t* coins );
   int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand( uint8_t* ct, uint8_t* ss,
                                                     const uint8_t* pk, const uint8_t* coins );
   int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec( uint8_t* ss, const uint8_t* ct,
                                              const uint8_t* sk );
   int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_derand( uint8_t* pk, uint8_t* sk,
                                                         const uint8_t* seed );
   int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx( const uint8_t* sig, size_t siglen,
                                                     const uint8_t* m, size_t mlen,
                                                     const uint8_t* ctx, size_t ctxlen,
                                                     const uint8_t* pk );
}

namespace {

constexpr auto KEM = fc::pq_algorithm::ml_kem_768;
constexpr auto DSA = fc::pq_algorithm::ml_dsa_65;

int g_failures = 0;
int g_checks   = 0;

void check( bool ok, const std::string& what )
{
   ++g_checks;
   if( !ok )
   {
      ++g_failures;
      std::cerr << "  FAIL: " << what << "\n";
   }
}

std::vector<uint8_t> unhex( const std::string& h )
{
   std::vector<uint8_t> out( h.size() / 2 );
   if( out.empty() )
      return out;
   size_t n = fc::from_hex( h, (char*)out.data(), out.size() );
   out.resize( n );
   return out;
}

/// Reports the first differing byte rather than just "not equal": when a KAT fails, where it
/// diverges says whether the problem is a wrong algorithm or a wrong encoding.
bool same( const std::vector<uint8_t>& got, const std::vector<uint8_t>& want,
           const std::string& label )
{
   if( got.size() != want.size() )
   {
      std::cerr << "    " << label << ": length " << got.size()
                << ", expected " << want.size() << "\n";
      return false;
   }
   for( size_t i = 0; i < got.size(); ++i )
      if( got[i] != want[i] )
      {
         std::cerr << "    " << label << ": first difference at byte " << i << "\n";
         return false;
      }
   return true;
}

fc::variants load( const std::string& file )
{
   const std::string path = std::string( FC_PQC_KAT_DIR ) + "/" + file;
   auto v = fc::json::from_file( fc::path( path ) );
   const auto& obj = v.get_object();
   std::cerr << file << ": " << obj["parameterSet"].as_string()
             << " " << obj["mode"].as_string() << "\n";
   return obj["tests"].get_array();
}

std::string str( const fc::variant_object& t, const char* key )
{
   return t.contains( key ) ? t[key].as_string() : std::string();
}

// ------------------------------------------------------------------ ML-KEM-768

void ml_kem_768_keygen()
{
   for( const auto& tv : load( "ml-kem-768-keygen.json" ) )
   {
      const auto& t = tv.get_object();
      auto d = unhex( str( t, "d" ) );
      auto z = unhex( str( t, "z" ) );

      // FIPS 203 keygen takes 64 bytes of coins, d || z
      std::vector<uint8_t> coins;
      coins.insert( coins.end(), d.begin(), d.end() );
      coins.insert( coins.end(), z.begin(), z.end() );

      std::vector<uint8_t> ek( fc::pqc_sizes::public_key_size( KEM ) ),
                           dk( fc::pqc_sizes::private_key_size( KEM ) );
      int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand( ek.data(), dk.data(),
                                                                 coins.data() );
      const std::string id = "keyGen tcId " + t["tcId"].as_string();
      check( 0 == rc, id + ": nonzero return" );
      check( same( ek, unhex( str( t, "ek" ) ), id + " ek" ), id + " ek" );
      check( same( dk, unhex( str( t, "dk" ) ), id + " dk" ), id + " dk" );
   }
}

void ml_kem_768_encap()
{
   for( const auto& tv : load( "ml-kem-768-encap.json" ) )
   {
      const auto& t = tv.get_object();
      auto ek = unhex( str( t, "ek" ) );
      auto m  = unhex( str( t, "m" ) );

      std::vector<uint8_t> ct( fc::pqc_sizes::ciphertext_size( KEM ) ),
                           ss( fc::pqc_sizes::shared_secret_size( KEM ) );
      int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand( ct.data(), ss.data(),
                                                             ek.data(), m.data() );
      const std::string id = "encap tcId " + t["tcId"].as_string();
      check( 0 == rc, id + ": nonzero return" );
      check( same( ct, unhex( str( t, "c" ) ), id + " c" ), id + " c" );
      check( same( ss, unhex( str( t, "k" ) ), id + " K" ), id + " K" );
   }
}

void ml_kem_768_decap()
{
   for( const auto& tv : load( "ml-kem-768-decap.json" ) )
   {
      const auto& t = tv.get_object();
      auto dk = unhex( str( t, "dk" ) );
      auto c  = unhex( str( t, "c" ) );

      std::vector<uint8_t> ss( fc::pqc_sizes::shared_secret_size( KEM ) );
      int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec( ss.data(), c.data(), dk.data() );

      // Some of these are implicit-rejection cases: FIPS 203 s7.3 requires decapsulation of a
      // malformed ciphertext to return a pseudorandom secret derived from the key's z value
      // rather than to fail. NIST supplies the exact expected value either way, which is what
      // makes them worth checking -- an implementation that "helpfully" errored out instead,
      // or that returned a constant, would leak whether a ciphertext was well-formed.
      const std::string id = "decap tcId " + t["tcId"].as_string()
                           + " (" + str( t, "reason" ) + ")";
      check( 0 == rc, id + ": nonzero return" );
      check( same( ss, unhex( str( t, "k" ) ), id + " K" ), id + " K" );
   }
}

// ------------------------------------------------------------------ ML-DSA-65

void ml_dsa_65_keygen()
{
   for( const auto& tv : load( "ml-dsa-65-keygen.json" ) )
   {
      const auto& t = tv.get_object();
      auto seed = unhex( str( t, "seed" ) );   // xi

      std::vector<uint8_t> pk( fc::pqc_sizes::public_key_size( DSA ) ),
                           sk( fc::pqc_sizes::private_key_size( DSA ) );
      int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_derand( pk.data(), sk.data(),
                                                                 seed.data() );
      const std::string id = "ML-DSA keyGen tcId " + t["tcId"].as_string();
      check( 0 == rc, id + ": nonzero return" );
      check( same( pk, unhex( str( t, "pk" ) ), id + " pk" ), id + " pk" );
      check( same( sk, unhex( str( t, "sk" ) ), id + " sk" ), id + " sk" );
   }
}

void ml_dsa_65_sigver()
{
   int valid_seen = 0, invalid_seen = 0;

   for( const auto& tv : load( "ml-dsa-65-sigver.json" ) )
   {
      const auto& t = tv.get_object();
      auto pk  = unhex( str( t, "pk" ) );
      auto msg = unhex( str( t, "message" ) );
      auto ctx = unhex( str( t, "context" ) );
      auto sig = unhex( str( t, "signature" ) );
      const bool expected = t["testPassed"].as_bool();

      int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                  sig.data(), sig.size(), msg.data(), msg.size(),
                  ctx.empty() ? nullptr : ctx.data(), ctx.size(), pk.data() );
      const bool accepted = ( 0 == rc );

      const std::string id = "sigVer tcId " + t["tcId"].as_string()
                           + " (" + str( t, "reason" ) + ")";
      check( accepted == expected,
             id + ( expected ? ": valid signature was rejected"
                             : ": TAMPERED SIGNATURE WAS ACCEPTED" ) );

      expected ? ++valid_seen : ++invalid_seen;
   }

   // Guard against the vector file being trimmed to only-valid cases at some point: a verifier
   // hardwired to return success would pass such a suite, so the negative cases are the ones
   // carrying the weight here.
   check( valid_seen > 0,   "sigVer: no valid-signature vectors were present" );
   check( invalid_seen > 0, "sigVer: no tampered-signature vectors were present" );
   std::cerr << "  (" << valid_seen << " valid, " << invalid_seen << " tampered)\n";
}

} // namespace

int main()
{
   try
   {
      ml_kem_768_keygen();
      ml_kem_768_encap();
      ml_kem_768_decap();
      ml_dsa_65_keygen();
      ml_dsa_65_sigver();
   }
   catch( const fc::exception& e )
   {
      std::cerr << "exception: " << e.to_detail_string() << "\n";
      return 1;
   }
   catch( const std::exception& e )
   {
      std::cerr << "exception: " << e.what() << "\n";
      return 1;
   }

   std::cerr << "\n" << ( g_checks - g_failures ) << "/" << g_checks
             << " conformance checks passed\n";
   if( g_failures > 0 )
   {
      std::cerr << g_failures << " FAILED\n";
      return 1;
   }
   // A silent pass with nothing checked would be indistinguishable from success.
   if( 0 == g_checks )
   {
      std::cerr << "no vectors were run\n";
      return 1;
   }
   std::cerr << "FIPS 203 / 204 conformance OK\n";
   return 0;
}
