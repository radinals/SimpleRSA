#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "logger.h"
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
        enum class UIMode {
                EncryptionMode,
                DecryptionMode
        };

	enum class UIStyle {
		LightMode,
		DarkMode,
	};

	enum class UILogMode {
		HIDDEN,
		SHOWN
	};

	enum class CustomKeyUIMode {
		HasNone,
		HasCustomDValueOnly,
		HasCustomEValueOnly,
		HasCustomDValueAndNValue,
		HasCustomEValueAndNValue,
		HasCustomNValueOnly,
	};

	bool using_custom_keys = false;
	bool has_front = false;
	bool has_back = false;

	UIStyle ui_style = UIStyle::LightMode;
	UILogMode ui_logmode = UILogMode::HIDDEN;
	UIMode current_mode = UIMode::EncryptionMode;

	const QString darkStyleSheet = ":/style/darkmode.qss";
	const QString lightStyleSheet = ":/style/lightmode.qss";

	std::string input_string;

	bool custom_key_size = false;
	bool text_is_encrypted = false;
	bool using_custom_pq = false;
	bool custom_p_entered = false;
	bool custom_q_entered = false;
	bool key_generated = false;

	mpz_class custom_p;
	mpz_class custom_q;

	mpz_class custom_n;
	mpz_class custom_d;
	mpz_class custom_e;

	RSAText plain_text;
	RSAText cypher_text;
	SimpleRSA rsa_engine;
	Logger logbox;

	void configure_ui();
	void configure_keysize_btn();
	void updateRSAInfo();
	void logRSAValues();
	void clearRSAInfo();
	void toggleLogView();
	void toggleInfoView();

      public:
        MainWindow(QWidget *parent = nullptr);
        ~MainWindow();

      private slots:
        void on_InputBox0Btn_pressed();

        void on_KeySizeBtn_128_pressed();

        void on_KeySizeBtn_512_pressed();

        void on_KeySizeBtn_2048_pressed();

        void on_ModeToggleBtn_pressed();

        void on_KeySizeCustomInput_returnPressed();

        void on_InputBox0Input_editingFinished();

        void on_KeySizeBtn_256_pressed();

        void on_RegenerateKeyButton_pressed();

        void on_ClearLog_clicked();

        void on_ProcPValueBox_editingFinished();

        void on_ProcQValueBox_editingFinished();

        void on_DarkModeBtn_clicked();

        void loadStyleSheet(const QString &filename);

        void on_ToggleLog_clicked();

        void on_ClearBtn_clicked();

        void on_ExitBtn_clicked();

        void on_ProcKeyFront_editingFinished();

        void on_ProcKeyBack_editingFinished();

      private:
        Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
