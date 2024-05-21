#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "rsatext.h"
#include "simplersa.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui
{
	class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
        Q_OBJECT

      private:
        enum class KeySize {
                KS_128,
                KS_256,
                KS_512,
                KS_1024,
        };

	enum class CustomKeyInputState {
		HasNoValue,
		HasPValue,
		HasQValue,
		HasPandQ,
	};

	enum class EncryptionModeState {
		HasNone,
		HasPublicKey,
		HasPlaintext,
		HasPublicKeyAndPlaintext,
	};

	enum class DecryptionModeState {
		HasNone,
		HasPrivateKey,
		HasCyphertext,
		HasPrivateKeyAndCyphertext,
	};

	const char m_KeyDelimiter = '|';
	const char m_CypherDelimiter = ';';

	KeySize m_keysize = KeySize::KS_128;

	DecryptionModeState m_decryption_mode_state =
	    DecryptionModeState::HasNone;

	EncryptionModeState m_encryption_mode_state =
	    EncryptionModeState::HasNone;

	CustomKeyInputState m_custom_key_state =
	    CustomKeyInputState::HasNoValue;

	mpz_class m_custom_key_p_value;
	mpz_class m_custom_key_q_value;

	RSAText m_Encryption_plaintext;
	RSAPublicKey m_Encryption_public_key;

	RSAText m_Decryption_cyphertext;
	RSAPrivateKey m_Decryption_private_key;

      public:
        MainWindow(QWidget *parent = nullptr);
        ~MainWindow();

      private slots:

        void on_AGK_SetKeySize1024_clicked();

        void on_AGK_SetKeySize512_clicked();

        void on_AGK_SetKeySize256_clicked();

        void on_AGK_SetKeySize128_clicked();

        void on_AGK_GenerateKeyBtn_clicked();

        void on_CKI_PValInput_editingFinished();

        void on_CKI_QValInput_editingFinished();

        void on_CKI_GenerateKeyBtn_clicked();

        void on_E_PublicKeyInput_editingFinished();

        void on_E_PlaintextInput_textChanged();

        void on_E_EncryptBtn_clicked();

        void on_D_PrivateKeyInput_editingFinished();

        void on_D_CyphertextInput_textChanged();

        void on_D_DecryptBtn_clicked();

        void on_ResetBtn_clicked();

        void on_ExitBtn_clicked();

      private:
        Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
