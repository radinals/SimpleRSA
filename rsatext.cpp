#include "rsatext.h"

RSAText::RSAText(const std::string &string)
{
	for (char ch : string) {
		m_vecstring.push_back(ch);
	}
}

std::string
RSAText::operator=(const std::string &string)
{
	if (!m_vecstring.empty())
		m_vecstring.clear();

	for (char ch : string) {
		m_vecstring.push_back(mpz_class(ch));
	}

	return getString();
}

std::string
RSAText::getString()
{
	std::string tmp;
	for (const mpz_class &ch : m_vecstring) {
		tmp += char(ch.get_ui());
	}
	return tmp;
}

std::string
RSAText::getAscii(std::string separator)
{
	std::string tmp;
	for (const mpz_class &ch : m_vecstring) {
		tmp += ch.get_str() + separator;
	}
	return tmp;
};

std::string
RSAText::getAscii(char separator)
{
	std::string tmp;
	for (const mpz_class &ch : m_vecstring) {
		tmp += ch.get_str() + separator;
	}
	return tmp;
};
