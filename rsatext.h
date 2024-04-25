#ifndef RSATEXT_H
#define RSATEXT_H

#include <gmpxx.h>
#include <string>
#include <vector>

class RSAText
{
      public:
        std::vector<mpz_class> m_vecstring;

	RSAText(){};
	RSAText(const std::string &string);
	std::string getAscii(std::string separator = "");
	std::string operator=(const std::string &string);
	std::string getString();

	inline void operator+=(mpz_class ch) { m_vecstring.push_back(ch); }
	inline void operator+=(unsigned int ch) { m_vecstring.push_back((ch)); }
};

#endif // RSATEXT_H
