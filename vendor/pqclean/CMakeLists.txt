# Vendored FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) reference implementations
# from PQClean (https://github.com/PQClean/PQClean, master 2026-08).
# Each module is a self-contained static library exposing the PQClean C API.
# randombytes() is supplied by fc (src/crypto/pqc.cpp).

set( PQCLEAN_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/fips202.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/ntt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/packing.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/poly.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/polyvec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/reduce.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/rounding.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/sign.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44/symmetric-shake.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/ntt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/packing.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/poly.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/polyvec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/reduce.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/rounding.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/sign.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65/symmetric-shake.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/ntt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/packing.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/poly.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/polyvec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/reduce.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/rounding.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/sign.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87/symmetric-shake.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/cbd.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/indcpa.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/kem.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/ntt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/poly.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/polyvec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/reduce.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/symmetric-shake.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512/verify.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/cbd.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/indcpa.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/kem.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/ntt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/poly.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/polyvec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/reduce.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/symmetric-shake.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768/verify.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/cbd.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/indcpa.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/kem.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/ntt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/poly.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/polyvec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/reduce.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/symmetric-shake.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024/verify.c
)

add_library( pqclean STATIC ${PQCLEAN_SOURCES} )
target_include_directories( pqclean
   PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-44
           ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-65
           ${CMAKE_CURRENT_SOURCE_DIR}/ml-dsa-87
           ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-512
           ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768
           ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-1024 )
set_target_properties( pqclean PROPERTIES POSITION_INDEPENDENT_CODE ON )