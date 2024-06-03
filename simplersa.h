#ifndef SIMPLERSA_H
#define SIMPLERSA_H

#include "rsatext.h"

#include <exception>
#include <gmpxx.h>
#include <utility>

struct RSAPrivateKey {
	mpz_class m_d;
	mpz_class m_n;
};

struct RSAPublicKey {
	mpz_class m_e;
	mpz_class m_n;
};

class SimpleRSA
{
      private:
	static mpz_class randomNumberGenerator(mp_bitcnt_t bits);
	static mpz_class randomRangeNumberGenerator(const mpz_class& min,
	                                            const mpz_class& max);

	static unsigned long rand_seed();

	static mpz_class randomPrime(unsigned int bits);

	static mpz_class gcd(mpz_class m, mpz_class n);

	static inline mpz_class eulerTotient(const mpz_class& p,
	                                     const mpz_class& q)
	{
		return (p - 1) * (q - 1);
	};

	static inline bool isCoprime(const mpz_class& m, const mpz_class& n)
	{
		return gcd(m, n) == 1;
	};

      public:
	SimpleRSA() = delete;
	SimpleRSA(SimpleRSA&) = delete;

	// fermat little theorem check
	static bool isFermatPrime(const mpz_class& number, unsigned int k = 0);

	static std::pair<RSAPublicKey, RSAPrivateKey> generate_key(
	    unsigned int bits = 128);

	static std::pair<RSAPublicKey, RSAPrivateKey> generate_key(
	    const mpz_class& p, const mpz_class& q);

	static RSAText decrypt(RSAText cyphertext, const mpz_class& d,
	                       const mpz_class& n);
	static RSAText encrypt(RSAText plaintext, const mpz_class& e,
	                       const mpz_class& n);

	static inline RSAText decrypt(RSAText cyphertext,
	                              const RSAPrivateKey& private_key)
	{
		return decrypt(cyphertext, private_key.m_d, private_key.m_n);
	}

	static inline RSAText encrypt(RSAText plaintext,
	                              const RSAPublicKey& public_key)
	{
		return encrypt(plaintext, public_key.m_e, public_key.m_n);
	}
};

namespace SimpleRSAException
{
	class QNotPrime : std::exception
	{
	      public:
		const char* what = "QNotPrime";
	};

	class PNotPrime : std::exception
	{
	      public:
		const char* what = "PNotPrime";
	};

	class PublicKeyNotPrime : std::exception
	{
	      public:
		const char* what = "PublicKeyNotPrime";
	};

	class NoModularInverseFound : std::exception
	{
	      public:
		const char* what = "NoModularInverseFound";
	};

} // namespace SimpleRSAException

#endif // SIMPLERSA_H
