#ifndef SIMPLERSA_H
#define SIMPLERSA_H

#include <gmpxx.h>
#include "rsatext.h"

class SimpleRSA
{
private:
    unsigned int m_primeBits = 128;
    mpz_class m_p;
    mpz_class m_q;
    mpz_class m_n;
    mpz_class m_phi;

    mpz_class m_private_key;
    mpz_class m_public_key;

    mpz_class encryptChar(mpz_class plain_char);
    mpz_class decryptChar(mpz_class cyphered_char);

    mpz_class randomNumberGenerator(mp_bitcnt_t bits);
    mpz_class randomRangeNumberGenerator(mpz_class min, mpz_class max);

    unsigned long rand_seed();

    mpz_class randomPrime();

    mpz_class gcd(mpz_class m, mpz_class n);

    inline mpz_class eulerTotient(mpz_class p, mpz_class q) { return (p - 1) * (q - 1); };

    inline bool isCoprime(mpz_class m, mpz_class n) { return gcd(m, n) == 1; };

    // fermat little theorem check
    bool isFermatPrime(mpz_class number, mpz_class k=0);

public:
    SimpleRSA() { generate_key(); };

    void generate_key();
    void generate_key(mpz_class p, mpz_class q);

    void setKeySize(unsigned int keysize)
    {
        m_primeBits = keysize;
        generate_key();
    };

    mpz_class getPValue() { return m_p; };
    mpz_class getQValue() { return m_q; };
    mpz_class getNValue() { return m_n; };
    mpz_class getPhiValue() { return m_phi; };
    mpz_class getPrivateKey() { return m_private_key; };
    mpz_class getPublicKey() { return m_public_key; };

    RSAText decrypt(RSAText cyphertext);
    RSAText encrypt(RSAText plaintext);
};

#endif // SIMPLERSA_H
