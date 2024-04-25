#include "simplersa.h"

#include <algorithm>
#include <climits>
#include <gmpxx.h>
#include <random>

unsigned long
SimpleRSA::rand_seed()
{
	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<unsigned long> dist(0, ULONG_MAX);
	return dist(rng);
}

mpz_class
SimpleRSA::randomRangeNumberGenerator(const mpz_class &min,
                                      const mpz_class &max)
{
	mpz_class rand_num;
	gmp_randclass rand(gmp_randinit_default);

	do {
		rand.seed(rand_seed());
		rand_num = rand.get_z_range(max);
	} while ((rand_num <= min) || (rand_num >= max));

	return rand_num;
}

mpz_class
SimpleRSA::randomNumberGenerator(mp_bitcnt_t bits)
{
	gmp_randclass rand(gmp_randinit_default);
	rand.seed(rand_seed());
	return rand.get_z_bits(bits);
}

bool
SimpleRSA::isFermatPrime(const mpz_class &number, unsigned int k)
{
	if (number <= 1) {
		return false;
	}

	if (number <= 3) {
		return true;
	}

	if (k <= 0) {
		k = 100;
	}

	for (mpz_class i = 0; i < k; i++) {
		mpz_class a = randomRangeNumberGenerator(2, number - 1);

		mpz_class num;

		// ( a^(number-1) ) % (number - 1)
		mpz_powm(num.get_mpz_t(), a.get_mpz_t(),
		         mpz_class(number - 1).get_mpz_t(), number.get_mpz_t());

		if (num != 1) {
			return false;
		}
	}

	return true;
}

mpz_class
SimpleRSA::gcd(mpz_class m, mpz_class n)
{
	while (n != 0) {
		mpz_class r = m % n;
		m = n;
		n = r;
	}
	return m;
}

mpz_class
SimpleRSA::randomPrime()
{
	mpz_class rand_prime;

	do {
		rand_prime = randomNumberGenerator(m_primeBits);
	} while (!isFermatPrime(rand_prime, 500));

	return rand_prime;
}

void
SimpleRSA::generate_key(const mpz_class &p, const mpz_class &q)
{
	if ((!isFermatPrime(p))) {
		throw SimpleRSAException::PNotPrime();
	}

	if ((!isFermatPrime(q))) {
		throw SimpleRSAException::QNotPrime();
	}

	m_p = p;
	m_q = q;

	m_n = (p * q);
	m_phi = eulerTotient(p, q);

	m_public_key = 127;
	while (m_public_key > 1 && m_public_key < m_phi) {
		if (isCoprime(m_public_key, m_phi)) {
			break;
		} else {
			m_public_key++;
		}
	}

	mpz_invert(m_private_key.get_mpz_t(), m_public_key.get_mpz_t(),
	           m_phi.get_mpz_t());
}

void
SimpleRSA::generate_key()
{
	// p != q
	do {
		m_p = randomPrime();
		m_q = randomPrime();
	} while ((m_p == m_q));

	m_n = (m_p * m_q);
	m_phi = eulerTotient(m_p, m_q);

	do {
		m_public_key = randomPrime();
	} while (m_public_key > 1 && m_public_key < m_phi &&
	         !isCoprime(m_public_key, m_phi));

	mpz_invert(m_private_key.get_mpz_t(), m_public_key.get_mpz_t(),
	           m_phi.get_mpz_t());
}

mpz_class
SimpleRSA::encryptChar(const mpz_class &plain_char, const mpz_class &public_key,
                       const mpz_class &n)
{
	mpz_class result;

	// result = ((character)^(m_public_key)) mod (m_n)
	mpz_powm(result.get_mpz_t(), plain_char.get_mpz_t(),
	         public_key.get_mpz_t(), n.get_mpz_t());

	return result;
}

mpz_class
SimpleRSA::decryptChar(const mpz_class &cypher_char,
                       const mpz_class &private_key, const mpz_class &n)
{
	mpz_class result;

	// result = ((character)^(m_public_key)) mod (m_n)
	mpz_powm(result.get_mpz_t(), cypher_char.get_mpz_t(),
	         private_key.get_mpz_t(), n.get_mpz_t());

	return result;
}

RSAText
SimpleRSA::decrypt(RSAText text, const mpz_class &private_key,
                   const mpz_class &n)
{
	auto convert = [&](mpz_class &ch) {
		ch = decryptChar(ch, private_key, n);
	};
	std::for_each(text.m_vecstring.begin(), text.m_vecstring.end(),
	              convert);
	return text;
}

RSAText
SimpleRSA::encrypt(RSAText text, const mpz_class &public_key,
                   const mpz_class &n)
{
	auto convert = [&](mpz_class &ch) {
		ch = encryptChar(ch, public_key, n);
	};
	std::for_each(text.m_vecstring.begin(), text.m_vecstring.end(),
	              convert);
	return text;
}
