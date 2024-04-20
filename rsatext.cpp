#include "rsatext.h"

RSAText::RSAText(const std::string &string)
{
	for (char ch : string) {
		m_charlist.push_back(ch);
	}
}

std::string
RSAText::operator=(const std::string &string)
{
	if (!m_charlist.empty())
		m_charlist.clear();

	for (char ch : string) {
		m_charlist.push_back(mpz_class(ch));
	}

	return getString();
}

void
RSAText::foreachChar(std::function<void(mpz_class &ch)> action)
{
	std::for_each(m_charlist.begin(), m_charlist.end(), action);
}

std::string
RSAText::getString()
{
	std::string tmp;
	for (mpz_class ch : m_charlist) {
		tmp += char(ch.get_ui());
	}
	return tmp;
}

std::string
RSAText::getAscii(std::string separator)
{
	std::string tmp;
	for (mpz_class ch : m_charlist) {
		tmp += std::to_string(ch.get_ui()) + separator;
	}
	return tmp;
};
