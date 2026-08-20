#pragma once
#include <boost/endian/buffers.hpp>

#include <fc/config.hpp>
#include <fc/container/flat_fwd.hpp>
#include <fc/io/varint.hpp>
#include <fc/safe.hpp>
#include <fc/uint128.hpp>

#include <array>
#include <deque>
#include <memory>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <set>

#define MAX_ARRAY_ALLOC_SIZE (1024*1024*10)

namespace fc {
   class time_point;
   class time_point_sec;
   class variant;
   class variant_object;
   class path;
   template<typename... Types> class static_variant;

   class sha224;
   class sha256;
   class sha512;
   class ripemd160;

   template<typename IntType, typename EnumType> class enum_type;
   namespace ip { class endpoint; }

   namespace ecc { class public_key; class private_key; }

   namespace raw {
    template<typename T>
    inline size_t pack_size(  const T& v );

    template<typename Stream, typename IntType, typename EnumType>
    inline void pack( Stream& s, const fc::enum_type<IntType,EnumType>& tp, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename IntType, typename EnumType>
    inline void unpack( Stream& s, fc::enum_type<IntType,EnumType>& tp, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream>
    inline void pack( Stream& s, const uint128_t& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream>
    inline void unpack( Stream& s, uint128_t& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename T> inline void pack( Stream& s, const std::set<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void unpack( Stream& s, std::set<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void pack( Stream& s, const std::unordered_set<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void unpack( Stream& s, std::unordered_set<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename... T> void pack( Stream& s, const static_variant<T...>& sv, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename... T> void unpack( Stream& s, static_variant<T...>& sv, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    //template<typename Stream, typename T> inline void pack( Stream& s, const flat_set<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    //template<typename Stream, typename T> inline void unpack( Stream& s, flat_set<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename T> inline void pack( Stream& s, const std::deque<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void unpack( Stream& s, std::deque<T>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename K, typename V> inline void pack( Stream& s, const std::unordered_map<K,V>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename K, typename V> inline void unpack( Stream& s, std::unordered_map<K,V>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename K, typename... V>
    inline void pack( Stream& s, const std::map<K, V...>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename K, typename V, typename... A>
    inline void unpack( Stream& s, std::map<K, V, A...>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    //template<typename Stream, typename K, typename... V> inline void pack( Stream& s, const flat_map<K,V...>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    //template<typename Stream, typename K, typename V, typename... A> inline void unpack( Stream& s, flat_map<K,V,A...>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename K, typename V> inline void pack( Stream& s, const std::pair<K,V>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename K, typename V> inline void unpack( Stream& s, std::pair<K,V>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> inline void pack( Stream& s, const variant_object& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, variant_object& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const variant& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, variant& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> inline void pack( Stream& s, const path& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, path& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const ip::endpoint& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, ip::endpoint& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );


    template<typename Stream, typename T> void unpack( Stream& s, fc::optional<T>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> void unpack( Stream& s, const T& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> void pack( Stream& s, const fc::optional<T>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> void pack( Stream& s, const safe<T>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> void unpack( Stream& s, fc::safe<T>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> void unpack( Stream& s, time_point&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void pack( Stream& s, const time_point&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void unpack( Stream& s, time_point_sec&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void pack( Stream& s, const time_point_sec&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void unpack( Stream& s, std::string&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void pack( Stream& s, const std::string&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void unpack( Stream& s, fc::ecc::public_key&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void pack( Stream& s, const fc::ecc::public_key&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void unpack( Stream& s, fc::ecc::private_key&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> void pack( Stream& s, const fc::ecc::private_key&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> inline void unpack( Stream& s, fc::sha224&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const fc::sha224&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, fc::sha256&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const fc::sha256&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, fc::sha512&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const fc::sha512&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, fc::ripemd160&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const fc::ripemd160&, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename T> void pack( Stream& s, const T& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> void unpack( Stream& s, T& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename T> inline void pack( Stream& s, const std::vector<T>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void unpack( Stream& s, std::vector<T>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> inline void pack( Stream& s, const unsigned_int& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, unsigned_int& vi, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> inline void pack( Stream& s, const char* v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void pack( Stream& s, const std::vector<char>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, std::vector<char>& value, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, boost::endian::order O, class T, std::size_t N, boost::endian::align A>
    inline void pack( Stream& s, const boost::endian::endian_buffer<O,T,N,A>& v, uint32_t _max_depth );
    template<typename Stream, boost::endian::order O, class T, std::size_t N, boost::endian::align A>
    inline void unpack( Stream& s, boost::endian::endian_buffer<O,T,N,A>& v, uint32_t _max_depth );

    template<typename Stream, typename T, size_t N>
    inline void pack( Stream& s, const std::array<T,N>& v, uint32_t _max_depth ) = delete;
    template<typename Stream, typename T, size_t N>
    inline void unpack( Stream& s, std::array<T,N>& v, uint32_t _max_depth ) = delete;
    template<typename Stream, size_t N>
    inline void pack( Stream& s, const std::array<char,N>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, size_t N>
    inline void unpack( Stream& s, std::array<char,N>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH);
    template<typename Stream, size_t N>
    inline void pack( Stream& s, const std::array<unsigned char,N>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, size_t N>
    inline void unpack( Stream& s, std::array<unsigned char,N>& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH);

    template<typename Stream, typename T> inline void pack( Stream& s, const std::shared_ptr<T>& v,
                                                            uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void unpack( Stream& s, std::shared_ptr<T>& v,
                                                              uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream, typename T> inline void pack( Stream& s, const std::shared_ptr<const T>& v,
                                                            uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream, typename T> inline void unpack( Stream& s, std::shared_ptr<const T>& v,
                                                              uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename Stream> inline void pack( Stream& s, const bool& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename Stream> inline void unpack( Stream& s, bool& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    template<typename T> inline std::vector<char> pack( const T& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename T> inline T unpack( const std::vector<char>& s, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename T> inline T unpack( const char* d, uint32_t s, uint32_t _max_depth=FC_PACK_MAX_DEPTH );
    template<typename T> inline void unpack( const char* d, uint32_t s, T& v, uint32_t _max_depth=FC_PACK_MAX_DEPTH );

    /**
     * Dual-format serialization context (defined in raw.hpp).
     * `legacy` reproduces the pre-PQ wire format; `current` includes pq_* fields.
     */
    enum class pq_format : uint8_t { legacy, current };
    pq_format get_pq_format();
    void set_pq_format( pq_format f );
    struct scoped_pq_format;
} }

namespace fc {

/**
 * A value that reaches the wire only under raw::pq_format::current.
 *
 * WHY THIS EXISTS, rather than each struct hand-writing a gated pack():
 *
 * fc's generic pack/unpack are templates, and the call they make to serialise a member is a
 * dependent one. Dependent names resolve against the declarations visible where the TEMPLATE
 * was defined -- here, inside fc -- plus ADL, which does not reach fc::raw. An overload
 * declared later in a downstream header is therefore invisible to them. A struct that reflects
 * a field AND hand-writes a gated pack() consequently has two different serialisers, and which
 * one a given call site gets depends on visibility and on whether the optimiser inlined the
 * generic template. That is not a gate; it is a coin flip that showed up as one extra byte in
 * a Release build and not in a Debug build of the same commit.
 *
 * Gating at the level of the field's TYPE, declared here in fc alongside the generics, is
 * visible to every path -- reflected or hand-written -- so the format decision cannot be
 * bypassed however the value is reached.
 *
 * It is transparent to JSON: to_variant/from_variant forward straight to the wrapped value, so
 * API and wallet shapes are unchanged.
 */
template<typename T>
struct pq_gated
{
   T value;

   pq_gated() = default;
   pq_gated( const T& v ) : value(v) {}                             // NOLINT: implicit on purpose
   pq_gated& operator=( const T& v ) { value = v; return *this; }

   operator const T&()const { return value; }                       // NOLINT: implicit on purpose
   operator T&() { return value; }

   // Forwarders so the wrapper is a drop-in for the container it wraps.
   auto begin()const { return value.begin(); }
   auto end()const   { return value.end(); }
   auto begin()      { return value.begin(); }
   auto end()        { return value.end(); }
   auto size()const  { return value.size(); }
   bool empty()const { return value.empty(); }
   void clear()      { value.clear(); }
   template<typename U> void push_back( U&& u ) { value.push_back( std::forward<U>(u) ); }
   template<typename U> auto insert( U&& u ) { return value.insert( std::forward<U>(u) ); }
   const auto& back()const { return value.back(); }
   auto& back() { return value.back(); }
   void reserve( size_t n ) { value.reserve( n ); }
   template<typename K> auto& operator[]( const K& k ) { return value[k]; }
   template<typename K> auto count( const K& k )const { return value.count( k ); }
   template<typename K> auto find( const K& k )const { return value.find( k ); }

   friend bool operator==( const pq_gated& a, const pq_gated& b ) { return a.value == b.value; }
   friend bool operator!=( const pq_gated& a, const pq_gated& b ) { return !(a == b); }
};

} // namespace fc

namespace fc { namespace raw {
   template<typename Stream, typename T>
   void pack( Stream& s, const fc::pq_gated<T>& v, uint32_t _max_depth = FC_PACK_MAX_DEPTH );
   template<typename Stream, typename T>
   void unpack( Stream& s, fc::pq_gated<T>& v, uint32_t _max_depth = FC_PACK_MAX_DEPTH );
} }

namespace fc {

class variant;

/// pq_gated is transparent to JSON: the wrapper gates the BINARY format only, so API and
/// wallet shapes are exactly what they were before the field became gated. Both bodies are
/// dependent on T, so `variant` need only be complete where they are instantiated.
template<typename T>
void to_variant( const pq_gated<T>& v, variant& vo, uint32_t max_depth )
{
   to_variant( v.value, vo, max_depth );
}
template<typename T>
void from_variant( const variant& var, pq_gated<T>& vo, uint32_t max_depth )
{
   from_variant( var, vo.value, max_depth );
}

}
