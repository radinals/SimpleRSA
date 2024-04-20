#include "simplersa.h"
#include <random>
#include <climits>

unsigned long SimpleRSA::rand_seed()
{
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<unsigned long> dist(0, ULONG_MAX);
    return dist(rng);
}

mpz_class SimpleRSA::randomRangeNumberGenerator(mpz_class min, mpz_class max)
{
    mpz_class rand_num;
    gmp_randclass rand(gmp_randinit_default);

    do {
        rand.seed(rand_seed());
        rand_num = rand.get_z_range(max);
    } while ((rand_num <= min) || (rand_num >= max));

    return rand_num;
}

mpz_class SimpleRSA::randomNumberGenerator(mp_bitcnt_t bits)
{
    gmp_randclass rand(gmp_randinit_default);
    rand.seed(rand_seed());
    return rand.get_z_bits(bits);
}

bool SimpleRSA::isFermatPrime(mpz_class number, mpz_class k)
{
    if (number <= 1) {
        return false;
    }

    if (number <= 3) {
        return true;
    }

    if (k <= 0) {
        k = number - 1;
    }

    for (mpz_class i = 0; i < k; i++) {
        mpz_class a = randomRangeNumberGenerator(2, number - 1);

        mpz_class num;

        // ( a^(number-1) ) % (number - 1)
        mpz_powm(num.get_mpz_t(),
                 a.get_mpz_t(),
                 mpz_class(number - 1).get_mpz_t(),
                 number.get_mpz_t());

        if (num != 1) {
            return false;
        }
    }

    return true;
}

mpz_class SimpleRSA::gcd(mpz_class m, mpz_class n)
{
    while (n != 0) {
        mpz_class r = m % n;
        m = n;
        n = r;
    }
    return m;
}

mpz_class SimpleRSA::randomPrime()
{
    mpz_class rand_prime;

    do {
        rand_prime = randomNumberGenerator(m_primeBits);
    } while (!isFermatPrime(rand_prime, 10));

    return rand_prime;
}

void SimpleRSA::generate_key(mpz_class p, mpz_class q)
{
    m_p = p;
    m_q = q;

    m_n = (p * q);
    m_phi = eulerTotient(p,q);

    // 1 < public_key < m_phi;
    do {
        m_public_key = randomRangeNumberGenerator(1, m_phi);
    } while (!isCoprime(m_public_key, m_phi));

    mpz_invert(m_private_key.get_mpz_t(), m_public_key.get_mpz_t(), m_phi.get_mpz_t());
}

void SimpleRSA::generate_key()
{
    // p != q
    do {
        m_p = randomPrime();
        m_q = randomPrime();
    } while ((m_p == m_q));

    m_n = (m_p * m_q);
    m_phi = eulerTotient(m_p, m_q);

    // 1 < public_key < m_phi;
    do {
        m_public_key = randomRangeNumberGenerator(1, m_phi);
    } while (!isCoprime(m_public_key, m_phi));

    mpz_invert(m_private_key.get_mpz_t(), m_public_key.get_mpz_t(), m_phi.get_mpz_t());
}

mpz_class SimpleRSA::encryptChar(mpz_class plain_char)
{
    mpz_class result;

    // result = ((character) ** (m_public_key)) mod (m_n)
    mpz_powm(result.get_mpz_t(), plain_char.get_mpz_t(), m_public_key.get_mpz_t(), m_n.get_mpz_t());

    return result;
}

mpz_class SimpleRSA::decryptChar(mpz_class cypher_char)
{
    mpz_class ch_mpz = cypher_char;

    mpz_class result;

    // result = ((character) ** (m_public_key)) mod (m_n)
    mpz_powm(result.get_mpz_t(), cypher_char.get_mpz_t(), m_private_key.get_mpz_t(), m_n.get_mpz_t());

    return result;
}

RSAText SimpleRSA::decrypt(RSAText text)
{
    auto convert = [&](mpz_class &ch) { ch = decryptChar(ch); };
    text.foreachChar(convert);
    return text;
}

RSAText SimpleRSA::encrypt(RSAText text) {

    auto convert = [&](mpz_class &ch) { ch = encryptChar(ch); };
    text.foreachChar(convert);
    return text;
}
