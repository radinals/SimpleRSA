#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QSizePolicy>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    rsa_engine = SimpleRSA();
    cypher_text = RSAText();
    plain_text = RSAText();
    updateRSAInfo();

    configure_ui();

    ui->KeySizeBtn_128->setChecked(true);
    ui->KeySizeBtn_256->setChecked(false);
    ui->KeySizeBtn_512->setChecked(false);
    ui->KeySizeBtn_2048->setChecked(false);

    logbox.setInstance(ui->LogTextBox);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::regenerateKeys()
{
    updateRSAInfo();
}

void MainWindow::updateRSAResult()
{
    ui->ProcPlaintextValueBox->setText(QString::fromStdString(plain_text.getString()));
    ui->ProcCyphertextValueBox->setText(QString::fromStdString(cypher_text.getString()));
}

void MainWindow::updateRSAInfo()
{
    QString p = QString::fromStdString(rsa_engine.getPValue().get_str());
    QString q = QString::fromStdString(rsa_engine.getQValue().get_str());
    QString n = QString::fromStdString(rsa_engine.getNValue().get_str());
    QString phi = QString::fromStdString(rsa_engine.getPhiValue().get_str());
    QString public_key = QString::fromStdString(rsa_engine.getPublicKey().get_str());
    QString private_key = QString::fromStdString(rsa_engine.getPrivateKey().get_str());

    ui->ProcQValueBox->setText(q);
    ui->ProcPValueBox->setText(p);
    ui->ProcPhiValueBox->setText(phi);
    ui->ProcNValueBox->setText(n);
    ui->ProcPrivateKeyValueBox->setText(private_key);
    ui->ProcPublickeyValueBox->setText(public_key);
}

void MainWindow::clearRSAInfo()
{
    ui->ProcQValueBox->clear();
    ui->ProcPValueBox->clear();
    ui->ProcPhiValueBox->clear();
    ui->ProcNValueBox->clear();
    ui->ProcPrivateKeyValueBox->clear();
    ui->ProcPublickeyValueBox->clear();
}

void MainWindow::configure_ui()
{
    if (current_mode == UIMode::EncryptionMode) {
        ui->ModeToggleBtn->setText("MODE: Encryption");
        ui->InputBox0Btn->setText("Encrypt");
        ui->InputBox0Input->setText(QString::fromStdString(plain_text.getString()));

        ui->KeySizeBtn_128->show();
        ui->KeySizeBtn_256->show();
        ui->KeySizeBtn_512->show();
        ui->KeySizeBtn_2048->show();
        ui->KeySizeCustomInput->show();
        ui->KeySizeLabel->show();

    } else if (current_mode == UIMode::DecryptionMode) {
        ui->ModeToggleBtn->setText("MODE: Decryption");
        ui->InputBox0Btn->setText("Decrypt");
        ui->InputBox0Input->setText(QString::fromStdString(cypher_text.getString()));

        ui->KeySizeBtn_128->hide();
        ui->KeySizeBtn_256->hide();
        ui->KeySizeBtn_512->hide();
        ui->KeySizeBtn_2048->hide();
        ui->KeySizeCustomInput->hide();
        ui->KeySizeLabel->hide();
    } else {
        throw std::runtime_error("Unknown Mode Reached");
    }
}

void MainWindow::on_InputBox0Btn_pressed()
{
    if (input_string.empty())
        return;
    if (current_mode == UIMode::EncryptionMode) {
        if (text_is_encrypted)
            return;
        cypher_text = rsa_engine.encrypt(plain_text);
        text_is_encrypted = true;
        logbox.sendLog(QString::fromStdString("####"));
        logbox.sendLog(cypher_text.getAscii());
    } else if (current_mode == UIMode::DecryptionMode) {
        if (!text_is_encrypted)
            return;
        plain_text = rsa_engine.decrypt(cypher_text);
        text_is_encrypted = false;
        logbox.sendLog(plain_text.getAscii());
        logbox.sendLog(plain_text.getString());
    } else {
        throw std::runtime_error("Unknown Mode Reached");
    }
    updateRSAResult();
}

void MainWindow::on_InputBox0Input_editingFinished()
{
    // do input checking if in DecryptionMode
    // if (current_mode == UIMode::EncryptionMode) {
    // }
    input_string = ui->InputBox0Input->text().toStdString();


    if (input_string.empty()) {
        ui->ProcPlaintextValueBox->clear();;
        ui->ProcCyphertextValueBox->clear();;
    }

    if (current_mode == UIMode::DecryptionMode) {
        ui->ProcPlaintextValueBox->setReadOnly(true);
    } else if (current_mode == UIMode::EncryptionMode) {
        ui->ProcPlaintextValueBox->setReadOnly(false);
        ui->ProcPlaintextValueBox->setText(ui->InputBox0Input->text());
        plain_text = input_string;
    }

}

void MainWindow::on_KeySizeBtn_128_pressed()
{
    ui->KeySizeCustomInput->clear();
    ui->KeySizeBtn_128->setChecked(true);
    ui->KeySizeBtn_256->setChecked(false);
    ui->KeySizeBtn_512->setChecked(false);
    ui->KeySizeBtn_2048->setChecked(false);

    clearRSAInfo();
    rsa_engine.setKeySize(128);
    updateRSAInfo();
}

void MainWindow::on_KeySizeBtn_512_pressed()
{
    ui->KeySizeCustomInput->clear();
    ui->KeySizeBtn_128->setChecked(false);
    ui->KeySizeBtn_256->setChecked(false);
    ui->KeySizeBtn_512->setChecked(true);
    ui->KeySizeBtn_2048->setChecked(false);

    clearRSAInfo();
    rsa_engine.setKeySize(512);
    updateRSAInfo();
}

void MainWindow::on_KeySizeBtn_2048_pressed()
{
    ui->KeySizeCustomInput->clear();
    ui->KeySizeBtn_128->setChecked(false);
    ui->KeySizeBtn_256->setChecked(false);
    ui->KeySizeBtn_512->setChecked(false);
    ui->KeySizeBtn_2048->setChecked(true);

    clearRSAInfo();
    rsa_engine.setKeySize(2048);
    updateRSAInfo();
}

void MainWindow::on_KeySizeBtn_256_pressed()
{
    ui->KeySizeCustomInput->clear();
    ui->KeySizeBtn_128->setChecked(false);
    ui->KeySizeBtn_256->setChecked(true);
    ui->KeySizeBtn_512->setChecked(false);
    ui->KeySizeBtn_2048->setChecked(false);

    clearRSAInfo();
    rsa_engine.setKeySize(256);
    updateRSAInfo();
}

void MainWindow::on_ModeToggleBtn_pressed()
{
    if (current_mode == UIMode::DecryptionMode) {
        current_mode = UIMode::EncryptionMode;
    } else if (current_mode == UIMode::EncryptionMode) {
        if (!text_is_encrypted)
            return;
        current_mode = UIMode::DecryptionMode;
    }
    configure_ui();
}

void MainWindow::on_KeySizeCustomInput_returnPressed()
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
        // TODO: SHOW ERROR
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

    clearRSAInfo();
    rsa_engine.setKeySize(key_size);
    updateRSAInfo();
}

void MainWindow::on_RegenerateKeyButton_pressed()
{
    clearRSAInfo();
    text_is_encrypted = false;
    rsa_engine.generate_key();
    updateRSAInfo();
}

