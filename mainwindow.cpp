#include "mainwindow.h"

#include "./ui_mainwindow.h"

#include <QDialog>
#include <QFile>
#include <QMessageBox>
#include <utility>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
	ui->setupUi(this);
	ui->AGK_SetKeySize128->setChecked(true);

	QFile file(":/style/lightmode.qss");
	file.open(QFile::ReadOnly);
	QString styleSheet = QLatin1String(file.readAll());
	this->setStyleSheet(styleSheet);
}

MainWindow::~MainWindow()
{
	delete ui;
}

void
MainWindow::on_AGK_SetKeySize1024_clicked()
{
	m_keysize = KeySize::KS_1024;
}

void
MainWindow::on_AGK_SetKeySize512_clicked()
{
	m_keysize = KeySize::KS_512;
}

void
MainWindow::on_AGK_SetKeySize256_clicked()
{
	m_keysize = KeySize::KS_256;
}

void
MainWindow::on_AGK_SetKeySize128_clicked()
{
	m_keysize = KeySize::KS_128;
}

void
MainWindow::on_AGK_GenerateKeyBtn_clicked()
{
	unsigned int bits = 128;
	switch (m_keysize) {
	case KeySize::KS_128:
		bits = 128;
		break;
	case KeySize::KS_256:
		bits = 256;
		break;
	case KeySize::KS_512:
		bits = 512;
		break;
	case KeySize::KS_1024:
		bits = 1024;
		break;
	}

	// pair<public key, private key>
	auto keys = SimpleRSA::generate_key(bits);

	std::string private_key = keys.second.m_d.get_str() + m_KeyDelimiter +
				  keys.second.m_n.get_str();

	std::string public_key = keys.first.m_e.get_str() + m_KeyDelimiter +
				 keys.first.m_n.get_str();

	ui->AGK_PrivateKeyOut->setText(QString::fromStdString(private_key));
	ui->AGK_PublicKeyOut->setText(QString::fromStdString(public_key));
}

void
MainWindow::on_CKI_PValInput_editingFinished()
{
	if (ui->CKI_PValInput->text().isEmpty()) {
		return;
	}

	if (m_custom_key_state == CustomKeyInputState::HasPValue) {
		m_custom_key_state = CustomKeyInputState::HasNoValue;
	} else if (m_custom_key_state == CustomKeyInputState::HasPandQ) {
		m_custom_key_state = CustomKeyInputState::HasQValue;
	}

	try {
		m_custom_key_p_value = ui->CKI_PValInput->text().toStdString();
		if (!SimpleRSA::isFermatPrime(m_custom_key_p_value, 100) ||
		    m_custom_key_p_value <= 10) {
			throw std::runtime_error("Incorrect P Value");
		}
	} catch (...) {
		QMessageBox messageBox;
		messageBox.critical(0, "Error", "P Value Is Invalid!");
		return;
	}

	if (m_custom_key_state == CustomKeyInputState::HasNoValue) {
		m_custom_key_state = CustomKeyInputState::HasPValue;
	} else {
		m_custom_key_state = CustomKeyInputState::HasPandQ;
	}
}

void
MainWindow::on_CKI_QValInput_editingFinished()
{
	if (ui->CKI_QValInput->text().isEmpty()) {
		return;
	}

	if (m_custom_key_state == CustomKeyInputState::HasQValue) {
		m_custom_key_state = CustomKeyInputState::HasNoValue;
	} else if (m_custom_key_state == CustomKeyInputState::HasPandQ) {
		m_custom_key_state = CustomKeyInputState::HasPValue;
	}

	try {
		m_custom_key_q_value = ui->CKI_QValInput->text().toStdString();
		if (!SimpleRSA::isFermatPrime(m_custom_key_q_value, 100) ||
		    m_custom_key_q_value <= 10) {
			throw std::runtime_error("Incorrect Q Value");
		}
	} catch (...) {
		QMessageBox messageBox;
		messageBox.critical(0, "Error", "Q Value Is Invalid!");
		return;
	}

	if (m_custom_key_state == CustomKeyInputState::HasNoValue) {
		m_custom_key_state = CustomKeyInputState::HasQValue;
	} else {
		m_custom_key_state = CustomKeyInputState::HasPandQ;
	}
}

void
MainWindow::on_CKI_GenerateKeyBtn_clicked()
{
	if (m_custom_key_state == CustomKeyInputState::HasPandQ) {

		// pair<public key, private key>
		auto keys = SimpleRSA::generate_key(m_custom_key_p_value,
						    m_custom_key_q_value);

		std::string private_key = keys.second.m_d.get_str() +
					  m_KeyDelimiter +
					  keys.second.m_n.get_str();

		std::string public_key = keys.first.m_e.get_str() +
					 m_KeyDelimiter +
					 keys.first.m_n.get_str();

		ui->CKI_PrivateKeyOut->setText(
		    QString::fromStdString(private_key));

		ui->CKI_PublicKeyOut->setText(
		    QString::fromStdString(public_key));

	} else {
		QMessageBox messageBox;
		messageBox.critical(0, "Error",
				    "P and Q values must be entered first!");
		return;
	}
}

void
MainWindow::on_E_PublicKeyInput_editingFinished()
{
	m_Encryption_public_key.m_e = 0;
	m_Encryption_public_key.m_n = 0;

	if (m_encryption_mode_state == EncryptionModeState::HasPublicKey) {
		m_encryption_mode_state = EncryptionModeState::HasNone;
	} else if (m_encryption_mode_state ==
		   EncryptionModeState::HasPublicKeyAndPlaintext) {
		m_encryption_mode_state = EncryptionModeState::HasPlaintext;
	}

	if (ui->E_PublicKeyInput->text().isEmpty()) {
		return;
	}

	std::string buffer;
	bool e_value_part = true;
	bool n_value_part = false;
	for (char ch : ui->E_PublicKeyInput->text().toStdString()) {
		if (ch == m_KeyDelimiter) {
			if (e_value_part) {
				m_Encryption_public_key.m_e = mpz_class(buffer);
				e_value_part = false;
				n_value_part = true;
			}
			buffer.clear();
			continue;
		} else if (ch >= '0' && ch <= '9') {
			buffer.push_back(ch);
		}
	}

	if (n_value_part) {
		m_Encryption_public_key.m_n = mpz_class(buffer);
		n_value_part = false;
	}

	if (n_value_part || e_value_part) {
		QMessageBox messageBox;
		messageBox.critical(0, "Error", "Public Key is Incomplete!");
		return;
	}

	if (m_encryption_mode_state == EncryptionModeState::HasPlaintext) {
		m_encryption_mode_state =
		    EncryptionModeState::HasPublicKeyAndPlaintext;
	} else {
		m_encryption_mode_state = EncryptionModeState::HasPublicKey;
	}
}

void
MainWindow::on_E_PlaintextInput_textChanged()
{
	if (m_encryption_mode_state == EncryptionModeState::HasPlaintext) {
		m_encryption_mode_state = EncryptionModeState::HasNone;
	} else if (m_encryption_mode_state ==
		   EncryptionModeState::HasPublicKeyAndPlaintext) {
		m_encryption_mode_state = EncryptionModeState::HasPublicKey;
	}

	if (ui->E_PlaintextInput->toPlainText().isEmpty()) {
		return;
	}

	m_Encryption_plaintext =
	    RSAText(ui->E_PlaintextInput->toPlainText().toStdString());

	if (m_encryption_mode_state == EncryptionModeState::HasPublicKey) {
		m_encryption_mode_state =
		    EncryptionModeState::HasPublicKeyAndPlaintext;
	} else {
		m_encryption_mode_state = EncryptionModeState::HasPlaintext;
	}
}

void
MainWindow::on_E_EncryptBtn_clicked()
{
	if (m_encryption_mode_state ==
	    EncryptionModeState::HasPublicKeyAndPlaintext) {
		RSAText cyphertext;
		cyphertext = SimpleRSA::encrypt(m_Encryption_plaintext,
						m_Encryption_public_key);
		ui->E_CyphertextOut->setPlainText(QString::fromStdString(
		    cyphertext.getAscii(m_CypherDelimiter)));
	} else {
		QMessageBox messageBox;
		messageBox.critical(
		    0, "Error",
		    "Public Key and Plaintext must be entered first!");
	}
}

void
MainWindow::on_D_PrivateKeyInput_editingFinished()
{
	m_Decryption_private_key.m_d = 0;
	m_Decryption_private_key.m_n = 0;
	if (m_decryption_mode_state == DecryptionModeState::HasPrivateKey) {
		m_decryption_mode_state = DecryptionModeState::HasNone;
	} else if (m_decryption_mode_state ==
		   DecryptionModeState::HasPrivateKeyAndCyphertext) {
		m_decryption_mode_state = DecryptionModeState::HasCyphertext;
	}

	if (ui->D_PrivateKeyInput->text().isEmpty()) {
		return;
	}

	std::string buffer;
	bool d_value_part = true;
	bool n_value_part = false;
	for (char ch : ui->D_PrivateKeyInput->text().toStdString()) {
		if (ch == m_KeyDelimiter) {
			if (d_value_part) {
				m_Decryption_private_key.m_d =
				    mpz_class(buffer);
				d_value_part = false;
				n_value_part = true;
			}
			buffer.clear();
			continue;
		} else if (ch >= '0' && ch <= '9') {
			buffer.push_back(ch);
		}
	}

	if (n_value_part) {
		m_Decryption_private_key.m_n = mpz_class(buffer);
		n_value_part = false;
	}

	if (n_value_part || d_value_part) {
		QMessageBox messageBox;
		messageBox.critical(0, "Error", "Private Key is Incomplete!");
		return;
	}

	if (m_decryption_mode_state == DecryptionModeState::HasCyphertext) {
		m_decryption_mode_state =
		    DecryptionModeState::HasPrivateKeyAndCyphertext;
	} else {
		m_decryption_mode_state = DecryptionModeState::HasPrivateKey;
	}
}

void
MainWindow::on_D_CyphertextInput_textChanged()
{
	m_Decryption_cyphertext.clear();

	if (m_decryption_mode_state == DecryptionModeState::HasCyphertext) {
		m_decryption_mode_state = DecryptionModeState::HasNone;
	} else if (m_decryption_mode_state ==
		   DecryptionModeState::HasPrivateKeyAndCyphertext) {
		m_decryption_mode_state = DecryptionModeState::HasPrivateKey;
	}

	if (ui->D_CyphertextInput->toPlainText().isEmpty()) {
		return;
	}

	std::string buffer;
	for (char ch : ui->D_CyphertextInput->toPlainText().toStdString()) {
		if (ch == m_CypherDelimiter) {
			m_Decryption_cyphertext += mpz_class(buffer);
			buffer.clear();
		} else if (ch >= '0' && ch <= '9') {
			buffer.push_back(ch);
		}
	}

	if (m_decryption_mode_state == DecryptionModeState::HasPrivateKey) {
		m_decryption_mode_state =
		    DecryptionModeState::HasPrivateKeyAndCyphertext;
	} else {
		m_decryption_mode_state = DecryptionModeState::HasCyphertext;
	}
}

void
MainWindow::on_D_DecryptBtn_clicked()
{
	if (m_decryption_mode_state ==
	    DecryptionModeState::HasPrivateKeyAndCyphertext) {
		RSAText plaintext;
		plaintext = SimpleRSA::decrypt(m_Decryption_cyphertext,
					       m_Decryption_private_key);
		ui->D_PlaintextOut->setPlainText(
		    QString::fromStdString(plaintext.getString()));
	} else {
		QMessageBox messageBox;
		messageBox.critical(
		    0, "Error",
		    "Private Key and Cyphertext must be entered first!");
	}
}

void
MainWindow::on_ResetBtn_clicked()
{
	m_decryption_mode_state = DecryptionModeState::HasNone;
	m_encryption_mode_state = EncryptionModeState::HasNone;
	m_custom_key_state = CustomKeyInputState::HasNoValue;
	m_keysize = KeySize::KS_128;

	m_custom_key_p_value = 0;
	m_custom_key_q_value = 0;

	m_Encryption_plaintext.clear();
	m_Encryption_public_key.m_e = 0;
	m_Encryption_public_key.m_n = 0;

	m_Decryption_cyphertext.clear();
	m_Decryption_private_key.m_d = 0;
	m_Decryption_private_key.m_n = 0;

	ui->AGK_PrivateKeyOut->clear();
	ui->AGK_PublicKeyOut->clear();
	ui->CKI_PrivateKeyOut->clear();
	ui->CKI_PublicKeyOut->clear();
	ui->CKI_PValInput->clear();
	ui->CKI_QValInput->clear();

	ui->D_PlaintextOut->clear();
	ui->D_CyphertextInput->clear();
	ui->D_PrivateKeyInput->clear();

	ui->E_PlaintextInput->clear();
	ui->E_CyphertextOut->clear();
	ui->E_PublicKeyInput->clear();
}

void
MainWindow::on_ExitBtn_clicked()
{
	exit(0);
}
