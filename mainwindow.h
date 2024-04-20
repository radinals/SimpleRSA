#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "simplersa.h"
#include "rsatext.h"
#include "logger.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    enum class UIMode { EncryptionMode, DecryptionMode };

    UIMode current_mode = UIMode::EncryptionMode;

    std::string input_string;

    bool custom_key_size = false;

    bool text_is_encrypted = false;
    RSAText plain_text;
    RSAText cypher_text;
    SimpleRSA rsa_engine;
    Logger logbox;

    void configure_ui();
    void configure_keysize_btn();
    void updateRSAInfo();
    void regenerateKeys();
    void clearRSAInfo();
    void updateRSAResult();

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_InputBox0Btn_pressed();

    // void on_InputBox0Input_returnPressed();

    void on_KeySizeBtn_128_pressed();

    void on_KeySizeBtn_512_pressed();

    void on_KeySizeBtn_2048_pressed();

    void on_ModeToggleBtn_pressed();

    void on_KeySizeCustomInput_returnPressed();

    void on_InputBox0Input_editingFinished();

    void on_KeySizeBtn_256_pressed();

    void on_RegenerateKeyButton_pressed();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
