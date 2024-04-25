#ifndef SIMPLERSA_H
#define SIMPLERSA_H

#include "rsatext.h"

#include <exception>
#include <gmpxx.h>

class SimpleRSA
{
      private:
        unsigned int m_primeBits = 128;
        mpz_class m_p;
        mpz_class m_q;
        mpz_class m_n;
        mpz_class m_phi;

	mpz_class m_d;
	mpz_class m_e;

	mpz_class encryptChar(const mpz_class& plain_char, const mpz_class& e,
			      const mpz_class& n);
	mpz_class decryptChar(const mpz_class& cypher_char, const mpz_class& d,
			      const mpz_class& n);

	inline mpz_class encryptChar(const mpz_class& plain_char)
	{
		return encryptChar(plain_char, m_e, m_n);
	}

	inline mpz_class decryptChar(const mpz_class& cypher_char)
	{
		return encryptChar(cypher_char, m_d, m_n);
	}

	mpz_class randomNumberGenerator(mp_bitcnt_t bits);
	mpz_class randomRangeNumberGenerator(const mpz_class& min,
					     const mpz_class& max);

	unsigned long rand_seed();

	mpz_class randomPrime();

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
        SimpleRSA(){};

	// fermat little theorem check
	bool isFermatPrime(const mpz_class& number, unsigned int k = 0);
	void generate_key();
	void generate_key(const mpz_class& p, const mpz_class& q);
	void setKeySize(unsigned int keysize) { m_primeBits = keysize; };

	inline mpz_class getPValue() { return m_p; };
	inline mpz_class getQValue() { return m_q; };
	inline mpz_class getNValue() { return m_n; };
	inline mpz_class getPhiValue() { return m_phi; };
	inline mpz_class getDValue() { return m_d; };
	inline mpz_class getEValue() { return m_e; };

	RSAText decrypt(RSAText cyphertext, const mpz_class& d,
			const mpz_class& n);
	RSAText encrypt(RSAText plaintext, const mpz_class& e,
			const mpz_class& n);

	inline RSAText decrypt(RSAText text)
	{
		return decrypt(text, getDValue(), getNValue());
	}

	inline RSAText encrypt(RSAText text)
	{
		return encrypt(text, getEValue(), getNValue());
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
		const char* what = "PublicKeyNotPrimeNotPrime";
	};

} // namespace SimpleRSAException

#endif // SIMPLERSA_H
