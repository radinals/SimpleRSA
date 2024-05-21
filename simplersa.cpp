#include "simplersa.h"

#include <algorithm>
#include <climits>
#include <gmpxx.h>
#include <random>
#include <stdexcept>

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

	for (mpz_class i = 5; i < k; i++) {
		mpz_class a = randomRangeNumberGenerator(5, number - 1);

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
SimpleRSA::randomPrime(unsigned int bits)
{
	mpz_class rand_prime;

	do {
		rand_prime = randomNumberGenerator(bits);
	} while (!isFermatPrime(rand_prime, 500));

	return rand_prime;
}

std::pair<RSAPublicKey, RSAPrivateKey>
SimpleRSA::generate_key(const mpz_class &p, const mpz_class &q)
{
	if ((!isFermatPrime(p))) {
		throw SimpleRSAException::PNotPrime();
	}

	if ((!isFermatPrime(q))) {
		throw SimpleRSAException::QNotPrime();
	}

	if (p == q) {
		throw std::invalid_argument("PQIsTheSame");
	}

	std::pair<RSAPublicKey, RSAPrivateKey> keys;
	mpz_class m, n;

	keys.second.m_n = keys.first.m_n = n = (p * q);
	m = eulerTotient(p, q);

	keys.first.m_e = 127;
	while (keys.first.m_e > 1 && keys.first.m_e < m) {
		if (isCoprime(keys.first.m_e, m)) {
			break;
		} else {
			keys.first.m_e++;
		}
	}

	// d = e x === 1 mod m
	mpz_invert(keys.second.m_d.get_mpz_t(), keys.first.m_e.get_mpz_t(),
		   m.get_mpz_t());

	return keys;
}

std::pair<RSAPublicKey, RSAPrivateKey>
SimpleRSA::generate_key(unsigned int bits)
{
	std::pair<RSAPublicKey, RSAPrivateKey> keys;
	mpz_class m, n, p, q;

	// p != q
	do {
		p = randomPrime(bits);
		q = randomPrime(bits);
	} while ((p == q));

	keys.second.m_n = keys.first.m_n = n = (p * q);
	m = eulerTotient(p, q);

	do {
		keys.first.m_e = randomPrime(bits);
	} while (keys.first.m_e > 1 && keys.first.m_e < m &&
		 !isCoprime(keys.first.m_e, m));

	// d = e x === 1 mod m
	mpz_invert(keys.second.m_d.get_mpz_t(), keys.first.m_e.get_mpz_t(),
		   m.get_mpz_t());

	return keys;
}

RSAText
SimpleRSA::decrypt(RSAText text, const mpz_class &d, const mpz_class &n)
{
	auto convert = [&](mpz_class &ch) {
		mpz_class result;
		// (ch ^ n) mod n
		mpz_powm(result.get_mpz_t(), ch.get_mpz_t(), d.get_mpz_t(),
			 n.get_mpz_t());
		ch = result;
	};
	std::for_each(text.m_vecstring.begin(), text.m_vecstring.end(),
		      convert);
	return text;
}

RSAText
SimpleRSA::encrypt(RSAText text, const mpz_class &e, const mpz_class &n)
{
	auto convert = [&](mpz_class &ch) {
		mpz_class result;
		// (ch ^ n) mod n
		mpz_powm(result.get_mpz_t(), ch.get_mpz_t(), e.get_mpz_t(),
			 n.get_mpz_t());
		ch = result;
	};

	std::for_each(text.m_vecstring.begin(), text.m_vecstring.end(),
		      convert);
	return text;
}
