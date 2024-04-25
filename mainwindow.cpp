#include "mainwindow.h"

#include "./ui_mainwindow.h"

// TODO: Rework the UI Logic

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
        ui->setupUi(this);

	rsa_engine = SimpleRSA();
	cypher_text = RSAText();
	plain_text = RSAText();
	logbox.setInstance(ui->LogTextBox);

	ui->KeySizeBtn_128->setChecked(true);
	ui->KeySizeBtn_256->setChecked(false);
	ui->KeySizeBtn_512->setChecked(false);
	ui->KeySizeBtn_2048->setChecked(false);
}

MainWindow::~MainWindow()
{
	delete ui;
}

void
MainWindow::logRSAValues()
{
	logbox.sendLog(std::string("START LOG"), Logger::LogLevel::NOPREFIX);

	logbox.sendLog(
	    std::string("Q VALUE: " + rsa_engine.getQValue().get_str()));

	logbox.sendLog(
	    std::string("P VALUE: " + rsa_engine.getPValue().get_str()));

	logbox.sendLog(
	    std::string("N = P * Q: " + rsa_engine.getNValue().get_str()));

	logbox.sendLog(std::string("PHI = (P-1) * (Q-1): " +
				   rsa_engine.getNValue().get_str()));

	logbox.sendLog(
	    std::string("E Value: " + rsa_engine.getDValue().get_str()));

	logbox.sendLog(
	    std::string("D Value: " + rsa_engine.getEValue().get_str()));

	logbox.sendLog(std::string("END LOG"), Logger::LogLevel::NOPREFIX);

	logbox.sendLog(std::string(""), Logger::LogLevel::NOPREFIX);
}

void
MainWindow::updateRSAInfo()
{
	QString p = QString::fromStdString(rsa_engine.getPValue().get_str());
	QString q = QString::fromStdString(rsa_engine.getQValue().get_str());
	QString n = QString::fromStdString(rsa_engine.getNValue().get_str());
	QString phi =
	    QString::fromStdString(rsa_engine.getPhiValue().get_str());
	QString d = QString::fromStdString(rsa_engine.getDValue().get_str());
	QString e = QString::fromStdString(rsa_engine.getEValue().get_str());
	QString public_key =
	    QString::fromStdString(rsa_engine.getDValue().get_str() + " " +
				   rsa_engine.getNValue().get_str());
	QString private_key =
	    QString::fromStdString(rsa_engine.getEValue().get_str() + " " +
				   rsa_engine.getNValue().get_str());

	ui->ProcQValueBox->setText(q);
	ui->ProcPValueBox->setText(p);
	ui->ProcNValueBox->setText(n);
	ui->ProcEValueBox->setText(e);
	ui->ProcDValueBox->setText(d);
	ui->ProcPhiValueBox->setText(phi);
	ui->ProcPrivateKeyValueBox->setText(private_key);
	ui->ProcPublickeyValueBox->setText(public_key);
}

void
MainWindow::clearRSAInfo()
{
	ui->ProcQValueBox->clear();
	ui->ProcPValueBox->clear();
	ui->ProcEValueBox->clear();
	ui->ProcDValueBox->clear();
	ui->ProcNValueBox->clear();
	ui->ProcResultBox->clear();
	ui->ProcPhiValueBox->clear();
	ui->ProcPrivateKeyValueBox->clear();
	ui->ProcPublickeyValueBox->clear();
}

void
MainWindow::configure_ui()
{
	if (current_mode == UIMode::EncryptionMode) {
		ui->ModeToggleBtn->setText("MODE: Encryption");
		ui->InputBox0Btn->setText("Encrypt");
		ui->InputBox0Input->setText(
		    QString::fromStdString(plain_text.getString()));

		ui->KeySizeBtn_128->setEnabled(true);
		ui->KeySizeBtn_256->setEnabled(true);
		ui->KeySizeBtn_512->setEnabled(true);
		ui->KeySizeBtn_2048->setEnabled(true);
		ui->KeySizeCustomInput->setEnabled(true);

	} else if (current_mode == UIMode::DecryptionMode) {
		ui->ModeToggleBtn->setText("MODE: Decryption");
		ui->InputBox0Btn->setText("Decrypt");
		ui->InputBox0Input->setText(
		    QString::fromStdString(cypher_text.getString()));

		ui->KeySizeBtn_128->setEnabled(false);
		ui->KeySizeBtn_256->setEnabled(false);
		ui->KeySizeBtn_512->setEnabled(false);
		ui->KeySizeBtn_2048->setEnabled(false);
		ui->KeySizeCustomInput->setEnabled(false);
	} else {
		throw std::runtime_error("Unknown Mode Reached");
	}
}

void
MainWindow::on_InputBox0Btn_pressed()
{
	if (input_string.empty() || !key_generated)
		return;
	if (current_mode == UIMode::EncryptionMode) {
		if (text_is_encrypted)
			return;
		cypher_text = rsa_engine.encrypt(plain_text);
		text_is_encrypted = true;

		logbox.sendLog(std::string("ENCRYPTION RESULT START"),
			       Logger::LogLevel::NOPREFIX);
		logbox.sendLog(
		    std::string("Cypher Text = " + cypher_text.getString()));
		logbox.sendLog(std::string("Cypher Text (ASCII) = " +
					   cypher_text.getAscii()));
		logbox.sendLog(std::string("ENCRYPTION RESULT END"),
			       Logger::LogLevel::NOPREFIX);
		logbox.sendLog(std::string(""), Logger::LogLevel::NOPREFIX);
		std::string Output =
		    plain_text.getString() + " --> " + cypher_text.getString();
		ui->ProcResultBox->setText(QString::fromStdString(Output));
	} else if (current_mode == UIMode::DecryptionMode) {
		if (!text_is_encrypted)
			return;
		plain_text = rsa_engine.decrypt(cypher_text);
		text_is_encrypted = false;
		logbox.sendLog(std::string("DECRYPTION RESULT START"),
			       Logger::LogLevel::NOPREFIX);
		logbox.sendLog(
		    std::string("Plain Text: " + plain_text.getString()));
		logbox.sendLog(
		    std::string("Plain Text (ASCII: " + plain_text.getAscii()));
		logbox.sendLog(std::string("DECRYPTION RESULT END"),
			       Logger::LogLevel::NOPREFIX);
		logbox.sendLog(std::string(""), Logger::LogLevel::NOPREFIX);
		std::string Output =
		    cypher_text.getString() + " --> " + plain_text.getString();
		ui->ProcResultBox->setText(QString::fromStdString(Output));
	} else {
		throw std::runtime_error("Unknown Mode Reached");
	}
}

void
MainWindow::on_InputBox0Input_editingFinished()
{
	if (current_mode == UIMode::EncryptionMode) {
		input_string = ui->InputBox0Input->text().toStdString();
		plain_text = input_string;
	}
}

void
MainWindow::on_KeySizeBtn_128_pressed()
{
	ui->KeySizeCustomInput->clear();
	ui->KeySizeBtn_128->setChecked(true);
	ui->KeySizeBtn_256->setChecked(false);
	ui->KeySizeBtn_512->setChecked(false);
	ui->KeySizeBtn_2048->setChecked(false);

	rsa_engine.setKeySize(128);
}

void
MainWindow::on_KeySizeBtn_512_pressed()
{
	ui->KeySizeCustomInput->clear();
	ui->KeySizeBtn_128->setChecked(false);
	ui->KeySizeBtn_256->setChecked(false);
	ui->KeySizeBtn_512->setChecked(true);
	ui->KeySizeBtn_2048->setChecked(false);

	rsa_engine.setKeySize(512);
}

void
MainWindow::on_KeySizeBtn_2048_pressed()
{
	ui->KeySizeCustomInput->clear();
	ui->KeySizeBtn_128->setChecked(false);
	ui->KeySizeBtn_256->setChecked(false);
	ui->KeySizeBtn_512->setChecked(false);
	ui->KeySizeBtn_2048->setChecked(true);

	rsa_engine.setKeySize(2048);
}

void
MainWindow::on_KeySizeBtn_256_pressed()
{
	ui->KeySizeCustomInput->clear();
	ui->KeySizeBtn_128->setChecked(false);
	ui->KeySizeBtn_256->setChecked(true);
	ui->KeySizeBtn_512->setChecked(false);
	ui->KeySizeBtn_2048->setChecked(false);

	rsa_engine.setKeySize(256);
}

void
MainWindow::on_ModeToggleBtn_pressed()
{
	if (current_mode == UIMode::DecryptionMode) {
		current_mode = UIMode::EncryptionMode;
		ui->InputBox0Input->setReadOnly(false);
	} else if (current_mode == UIMode::EncryptionMode) {
		if (!text_is_encrypted)
			return;
		ui->InputBox0Input->setReadOnly(true);
		current_mode = UIMode::DecryptionMode;
	}
	configure_ui();
}

void
MainWindow::on_KeySizeCustomInput_returnPressed()
{
	std::string input = ui->KeySizeCustomInput->text().toStdString();

	if (input.empty()) {
		ui->KeySizeCustomInput->clear();
		ui->KeySizeBtn_128->setEnabled(true);
		ui->KeySizeBtn_256->setEnabled(true);
		ui->KeySizeBtn_512->setEnabled(true);
		ui->KeySizeBtn_2048->setEnabled(true);
		return;
	}

	unsigned long key_size = 0;

	try {
		key_size = std::stoul(input);
	} catch (...) {
		ui->KeySizeCustomInput->clear();
		ui->KeySizeBtn_128->setEnabled(true);
		ui->KeySizeBtn_512->setEnabled(true);
		ui->KeySizeBtn_256->setEnabled(true);
		ui->KeySizeBtn_2048->setEnabled(true);
		return;
	}

	ui->KeySizeBtn_128->setEnabled(false);
	ui->KeySizeBtn_512->setEnabled(false);
	ui->KeySizeBtn_256->setEnabled(false);
	ui->KeySizeBtn_2048->setEnabled(false);

	rsa_engine.setKeySize(key_size);
}

void
MainWindow::on_RegenerateKeyButton_pressed()
{
	clearRSAInfo();
	text_is_encrypted = false;
	using_custom_pq = false;
	custom_p_entered = false;
	custom_q_entered = false;
	key_generated = true;
	rsa_engine.generate_key();
	updateRSAInfo();
	logRSAValues();
}

void
MainWindow::on_ClearLog_clicked()
{
	ui->LogTextBox->clear();
}

void
MainWindow::on_ProcPValueBox_editingFinished()
{
	if (!using_custom_pq) {
		ui->ProcQValueBox->clear();
		ui->ProcPhiValueBox->clear();
		ui->ProcNValueBox->clear();
		ui->ProcPrivateKeyValueBox->clear();
		ui->ProcPublickeyValueBox->clear();
		ui->ProcResultBox->clear();
	}

	if (custom_p_entered && custom_q_entered && using_custom_pq) {
		custom_p_entered = false;
		custom_q_entered = false;
		using_custom_pq = false;
	}

	if (!custom_q_entered && !custom_p_entered && !using_custom_pq) {
		try {
			custom_p = ui->ProcPValueBox->text().toStdString();
		} catch (...) {
			ui->ProcPValueBox->clear();
			return;
		}

		if (!rsa_engine.isFermatPrime(custom_p)) {
			logbox.sendLog(std::string("P is not a prime number!"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcPValueBox->clear();
			return;
		}

		if (custom_p <= 10) {
			logbox.sendLog(std::string("P Needs to be > 10"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcPValueBox->clear();
			return;
		}

		custom_p_entered = true;
		using_custom_pq = true;

		return;
	}

	if (custom_q_entered && !custom_p_entered && using_custom_pq) {
		try {
			custom_p = ui->ProcPValueBox->text().toStdString();
		} catch (...) {
			ui->ProcPValueBox->clear();
			return;
		}

		if (!rsa_engine.isFermatPrime(custom_p)) {
			logbox.sendLog(std::string("P is not a prime number!"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcPValueBox->clear();
			return;
		}

		if (custom_p <= 10) {
			logbox.sendLog(std::string("P Needs to be > 10"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcPValueBox->clear();
			return;
		}

		if (custom_p == custom_q) {
			logbox.sendLog(std::string("P and Q must be different"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcPValueBox->clear();
			return;
		}

		text_is_encrypted = false;
		custom_p_entered = true;

		rsa_engine.generate_key(custom_p, custom_q);
		key_generated = true;
		updateRSAInfo();
		logRSAValues();
	}
}

void
MainWindow::on_ProcQValueBox_editingFinished()
{
	if (!using_custom_pq) {
		ui->ProcPValueBox->clear();
		ui->ProcNValueBox->clear();
		ui->ProcEValueBox->clear();
		ui->ProcDValueBox->clear();
		ui->ProcResultBox->clear();
		ui->ProcPhiValueBox->clear();
		ui->ProcPrivateKeyValueBox->clear();
		ui->ProcPublickeyValueBox->clear();
	}

	if (custom_p_entered && custom_q_entered && using_custom_pq) {
		custom_p_entered = false;
		custom_q_entered = false;
		using_custom_pq = false;
	}

	if (!custom_q_entered && !custom_p_entered && !using_custom_pq) {
		try {
			custom_q = ui->ProcQValueBox->text().toStdString();
		} catch (...) {
			ui->ProcQValueBox->clear();
			return;
		}

		if (!rsa_engine.isFermatPrime(custom_q)) {
			logbox.sendLog(std::string("Q is not a prime number!"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcQValueBox->clear();
			return;
		}

		if (custom_q <= 10) {
			logbox.sendLog(std::string("Q Needs to be > 10"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcQValueBox->clear();
			return;
		}

		custom_q_entered = true;
		using_custom_pq = true;

		return;
	}

	if (custom_p_entered && !custom_q_entered && using_custom_pq) {
		try {
			custom_q = ui->ProcQValueBox->text().toStdString();
		} catch (...) {
			ui->ProcQValueBox->clear();
			return;
		}

		if (!rsa_engine.isFermatPrime(custom_q)) {
			logbox.sendLog(std::string("Q is not a prime number!"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcQValueBox->clear();
			return;
		}

		if (custom_q <= 10) {
			logbox.sendLog(std::string("Q Needs to be > 10"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcQValueBox->clear();
			return;
		}

		if (custom_p == custom_q) {
			logbox.sendLog(std::string("P and Q must be different"),
				       Logger::LogLevel::ERROR);
			logbox.sendLog(std::string(""),
				       Logger::LogLevel::NOPREFIX);
			ui->ProcQValueBox->clear();
			return;
		}

		text_is_encrypted = false;
		custom_q_entered = true;

		rsa_engine.generate_key(custom_p, custom_q);
		key_generated = true;
		updateRSAInfo();
		logRSAValues();
	}
}
