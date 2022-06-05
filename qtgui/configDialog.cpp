#include "configDialog.h"
#include "Config.h"
#include "ui_configDialog.h"
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QMessageBox>

ConfigDialog::ConfigDialog(QWidget* parent)
    : QDialog(parent), m_ui(new Ui::ConfigDialog)
{
    m_ui->setupUi(this);
    connect(this, SIGNAL(accepted()), SLOT(saveSettings()));
    // connect(this, SIGNAL(rejected()), SLOT(reject()));
    loadSettings();
}

ConfigDialog::~ConfigDialog() {}

void ConfigDialog::loadSettings()
{
    if (config()->hasAccessError()) {
        QString warn_text = QString(tr("Access error for config file %1").arg(config()->getFileName()));
        QMessageBox::warning(this, tr("Could not load configuration"), warn_text);
    }


    m_ui->comboStrength->setCurrentIndex(config()->get(Config::CRYPTO_Strength).toInt());
    m_ui->comboAlgo->setCurrentIndex(config()->get(Config::CRYPTO_algorithm).toInt());
}

void ConfigDialog::saveSettings()
{
    config()->set(Config::CRYPTO_Strength, m_ui->comboStrength->currentIndex());
    config()->set(Config::CRYPTO_algorithm, m_ui->comboAlgo->currentIndex());
}
