#ifndef RSATEXT_H
#define RSATEXT_H

#include <functional>
#include <gmpxx.h>
#include <string>
#include <vector>

class RSAText
{
      private:
	std::vector<mpz_class> m_charlist;

      public:
	RSAText(){};
	RSAText(const std::string &string);
	std::string getAscii(std::string separator = "");
	std::string operator=(const std::string &string);
	void foreachChar(std::function<void(mpz_class &)>);
	std::string getString();
	inline void operator+=(mpz_class ch) { m_charlist.push_back(ch); }
	inline void operator+=(unsigned int ch) { m_charlist.push_back((ch)); }
};

#endif // RSATEXT_H
