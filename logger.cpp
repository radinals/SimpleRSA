#include "logger.h"

void
Logger::sendString(const QString &string, Colors color)
{
	m_textEditInstance->append(setStringColor(string, color));
}

QString
Logger::setStringColor(const QString &string, Colors color)
{
	QString formatted;
	switch (color) {
	case Colors::WHITE:
		formatted = QString("<span style=\" color:#ffffff; \">" +
				    string + "</span>");
		break;
	case Colors::RED:
		formatted = QString("<span style=\" color:#C0392B; \">" +
				    string + "</span>");
		break;
	case Colors::GREEN:
		formatted = QString("<span style=\" color:#27AE60; \">" +
				    string + "</span>");
		break;
	case Colors::BLUE:
		formatted = QString("<span style=\" color:#2E86C1; \">" +
				    string + "</span>");
		break;
	case Colors::YELLOW:
		formatted = QString("<span style=\" color:#F1C40F; \">" +
				    string + "</span>");
		break;

	default:
		formatted = QString("<span style=\" color:#000000; \">" +
				    string + "</span>");
		break;
	}

	return formatted;
}

void
Logger::sendLog(const QString &log, LogLevel level, Colors color)
{
	switch (level) {
	case LogLevel::NOTICE:
		if (color == Colors::NONE)
			color = Colors::BLUE;
		sendString("NOTICE: " + log, color);
		break;
	case LogLevel::WARNING:
		if (color == Colors::NONE)
			color = Colors::YELLOW;
		sendString("WARNING: " + log, color);
		break;
	case LogLevel::ERROR:
		if (color == Colors::NONE)
			color = Colors::RED;
		sendString("ERROR: " + log, color);
		break;
	case LogLevel::NORMAL:
		if (color == Colors::NONE)
			color = Colors::BLACK;
		sendString("LOG: " + log, color);
		break;
	default:
		if (color == Colors::NONE)
			color = Colors::BLACK;
		sendString(log, color);
		break;
	}
}
