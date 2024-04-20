#ifndef LOGGER_H
#define LOGGER_H

#include <QString>
#include <QTextEdit>

class Logger
{
      public:
	enum class LogLevel {
		NORMAL,
		NOTICE,
		WARNING,
		ERROR,
	};

	enum class Colors {
		NONE,
		BLACK,
		WHITE,
		RED,
		GREEN,
		BLUE,
		YELLOW,
	};

      private:
	void sendString(const QString &string, Colors color);
	QTextEdit *m_textEditInstance = nullptr;
	QString setStringColor(const QString &string, Colors color);

      public:
	Logger(){};
	Logger(QTextEdit *&textEditInstance)
	    : m_textEditInstance(textEditInstance){};
	void setInstance(QTextEdit *&textEditInstance)
	{
		m_textEditInstance = textEditInstance;
	};
	void sendLog(const QString &log, LogLevel level = LogLevel::NORMAL,
	             Colors color_override = Colors::NONE);
	void sendLog(const std::string &log, LogLevel level = LogLevel::NORMAL,
	             Colors color_override = Colors::NONE);
};

#endif // LOGGER_H
