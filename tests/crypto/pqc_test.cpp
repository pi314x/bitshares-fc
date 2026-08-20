#include <fc/crypto/pqc.hpp>
#include <fc/io/datastream.hpp>
#include <fc/io/raw.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/exception/exception.hpp>

#include <iostream>
#include <string>

int main()
{
   try
   {
      // ML-DSA round trip for all parameter sets
      for( fc::pq_algorithm alg : { fc::pq_algorithm::ml_dsa_44,
                                    fc::pq_algorithm::ml_dsa_65,
                                    fc::pq_algorithm::ml_dsa_87 } )
      {
         auto kp = fc::pq_generate_keypair( alg );
         std::cerr << "ML-DSA alg=" << (int)kp.priv.alg_
                   << " pk=" << kp.pub.data().size()
                   << " sk=" << kp.priv.key_.size() << "\n";

         assert( kp.valid() );
         assert( kp.pub == kp.priv.get_public_key() );

         fc::sha256 digest = fc::sha256::hash( "post quantum bitshares", 23 );
         auto sig = kp.priv.sign( digest );
         assert( sig.size() == fc::pqc_sizes::signature_size( alg ) );
         assert( kp.pub.verify( digest, sig ) );

         fc::sha256 other = fc::sha256::hash( "tampered", 8 );
         assert( !kp.pub.verify( other, sig ) );
         auto bad = sig;
         bad[0] ^= 0xFF;
         assert( !kp.pub.verify( digest, bad ) );

         // deterministic re-derivation from seed
         fc::sha256 seed = fc::sha256::hash( "seed-material", 13 );
         auto a = fc::pq_generate_keypair_from_seed( alg, seed );
         auto b = fc::pq_generate_keypair_from_seed( alg, seed );
         assert( a.pub == b.pub );
         assert( a.priv.key_ == b.priv.key_ );

         // signature is hedged (FIPS 204 rnd != 0): repeated signs differ
         // but all verify.
         assert( a.pub.verify( digest, a.priv.sign( digest ) ) );
         assert( a.pub.verify( digest, a.priv.sign( digest ) ) );

         // base58 round trip
         auto b58 = a.pub.to_base58();
         assert( fc::pq_public_key::from_base58( b58 ) == a.pub );

         // raw serialization round trip
         fc::datastream<size_t> sz;
         fc::raw::pack( sz, a.priv );
         std::vector<char> buf( sz.tellp() );
         fc::datastream<char*> ds( buf.data(), buf.size() );
         fc::raw::pack( ds, a.priv );
         fc::pq_private_key priv2;
         fc::datastream<const char*> ds2( buf.data(), buf.size() );
         fc::raw::unpack( ds2, priv2 );
         assert( priv2 == a.priv );

         // variant round trip
         fc::variant v;
         fc::to_variant( a.pub, v, 2 );
         fc::pq_public_key pub2;
         fc::from_variant( v, pub2, 2 );
         assert( pub2 == a.pub );
      }

      // ML-KEM round trip for all parameter sets
      for( fc::pq_algorithm alg : { fc::pq_algorithm::ml_kem_512,
                                    fc::pq_algorithm::ml_kem_768,
                                    fc::pq_algorithm::ml_kem_1024 } )
      {
         auto kkp = fc::pq_kem_generate( alg );
         auto enc = fc::pq_kem_encapsulate( alg, kkp.pk );
         auto dec = fc::pq_kem_decapsulate( alg, kkp.sk, enc.ciphertext );
         assert( enc.valid );
         assert( enc.shared_secret == dec );
         std::cout << " ML-KEM alg=" << (int)alg
                   << " ct=" << enc.ciphertext.size() << " ok\n";
      }

      std::cout << "ALL PQC TESTS PASSED" << std::endl;
      return 0;
   }
   catch( const fc::exception& e )
   {
      std::cerr << "FAILED: " << e.to_string() << std::endl;
      return 1;
   }
}