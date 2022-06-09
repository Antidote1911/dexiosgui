#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "QMainWindow"
#include <QMessageBox>
#include <QComboBox>
#include <QProgressBar>
#include <QActionGroup>
#include <QDebug>
#include "adapter.h"
#include "Config.h"
#include "configDialog.h"
#include "skin/skin.h"

MainWindow::MainWindow(QWidget *parent)
        : QMainWindow(parent),
          m_ui(std::make_unique<Ui::MainWindow>()) {
          m_ui->setupUi(this);
          m_ui->progBar->setVisible(false);
          loadPreferences();
          initViewMenu();
          applyTheme();

    connect(m_ui->menu_About, &QAction::triggered, this, [=] { slot_menuAbout(); });
    connect(m_ui->menu_AboutQt, &QAction::triggered, this, [=] { QMessageBox::aboutQt(this); });
    connect(m_ui->menu_Open, &QAction::triggered, this, [=] { slot_Open(); });
    connect(m_ui->menu_Quit, &QAction::triggered, this, [=] { QApplication::quit(); });
    connect(m_ui->actionCrypto, &QAction::triggered, this,  [=] { configuration(); });
    //connect(m_ui->comboAlgo, SIGNAL(currentIndexChanged(int)), this, SLOT(savePreferences()));
}

MainWindow::~MainWindow() = default;

void MainWindow::configuration()
{
    auto *confDialog = new ConfigDialog(this);
    confDialog->exec();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);
    // save prefs before quitting
    savePreferences();

}

void MainWindow::initViewMenu()
{
    setContextMenuPolicy(Qt::NoContextMenu);

    m_ui->actionDark->setData("dark");
    m_ui->actionLight->setData("classic");

    auto themeActions = new QActionGroup(this);
    themeActions->addAction(m_ui->actionDark);
    themeActions->addAction(m_ui->actionLight);

    auto theme = config()->get(Config::GUI_ApplicationTheme).toString();
    for (auto action : themeActions->actions()) {
        if (action->data() == theme) {
            action->setChecked(true);
            break;
        }
    }

    connect(themeActions, &QActionGroup::triggered, this, [this](QAction *action) {
        if (action->data() != config()->get(Config::GUI_ApplicationTheme)) {
            config()->set(Config::GUI_ApplicationTheme, action->data());
            restartApp();
        }
    });
}

void MainWindow::restartApp()
{
    int ret = QMessageBox::question(this, tr("Restart Application ?"),
                                    tr("To take effect, DexiosGUI need to be restarted.\n"
                                       "Do you want to restart now ?"),
                                    QMessageBox::No | QMessageBox::Yes,
                                    QMessageBox::Yes);

    if (ret == QMessageBox::Yes) {
        close();
        reboot();
    }
}

void MainWindow::reboot()
{
    qDebug() << "Performing application reboot...";
    qApp->exit(-123456789);
}

void MainWindow::loadPreferences()
{
    if (config()->hasAccessError()) {
        auto warn_text = QString(tr("Access error for config file %1").arg(config()->getFileName()));
        QMessageBox::warning(this, tr("Could not load configuration"), warn_text);
    }

    restoreGeometry(config()->get(Config::GUI_MainWindowGeometry).toByteArray());
    restoreState(config()->get(Config::GUI_MainWindowState).toByteArray());

}

void MainWindow::savePreferences()
{
        config()->set(Config::GUI_MainWindowGeometry, saveGeometry());
        config()->set(Config::GUI_MainWindowState,    saveState());
    // clang-format on
}

void MainWindow::applyTheme()
{
    QString appTheme = config()->get(Config::GUI_ApplicationTheme).toString();
    if (appTheme == "classic") {
        skin()->setSkin("classic");
    }
    else if (appTheme == "dark") {
        skin()->setSkin("dark");
    }
    else {
    }
}

void MainWindow::slot_menuAbout() {
    auto Str = get_version2();

    QMessageBox::about(this, "About DexiosGUI",
                       "<h2>DexiosGUI</h2>"
                       "Core Version: " + QString::fromStdString(Str) +
                       "<p>Copyright (C) Antidote1911 2022 for c++ GUI</p>"
                       "<p>Copyright (C) brxken128  2022 for the rust core crypto</p>"
                       "<p>Licensed under the GNU General Public License v3.0</p>"
                       "<p><a href=\"https://github.com/Antidote1911/dexiosgui\">DexiosGUI GitHub</a></p>"
                       "<p><a href=\"https://github.com/brxken128/dexios-core\">Dexios core crypto GitHub</a></p>"
                       "<p><b>WARNING:</b> if you encrypt a file and lose or forget the password, the file cannot be recovered.</p>");
}

void MainWindow::updateProgress(int percentage) {
    if (!this->m_ui->progBar->isVisible()) {
        this->m_ui->progBar->setVisible(true);
    }
    this->m_ui->progBar->setValue(percentage);
}

void MainWindow::slot_Open()
{
    QString password, outFilename;
    QMessageBox msgBox;
    // Open a file dialog to get file
    const auto filename = QFileDialog::getOpenFileName(this, tr("Open File"));
    if (filename.isEmpty()) // if no file selected
    {
        return;
    }
    m_ui->label->setBackgroundRole(QPalette::Highlight);
    Direction mode = getDirection(filename);

    Outcome o;
    do {
        o = passwordPrompts(mode, &password);
        if (o == cancel) {
            m_ui->label->clear();
            return;
        }
    } while (o);

    do {
        outFilename = saveDialog(filename, mode);
        if (outFilename == "") {
            // user hit cancel
            m_ui->label->clear();
            return;
        }
        else if (QFileInfo::exists(outFilename)) {
            // warn and redo
            msgBox.setText("Must select filename that does not already exist.");
            msgBox.exec();
            o = redo;
        }
        else {
            o = success;
        }
    } while (o);

    m_ui->label->setText("Working...");
    cryptoConfig = makeConfig(mode,
                              config()->get(Config::CRYPTO_algorithm).toInt(),
                              password.toUtf8().data(),
                              filename.toUtf8().data(),
                              outFilename.toUtf8().data(),
                              output);

    if (cryptoConfig == nullptr) {
        msgBox.setText("Could not start transfer, possibly due to malformed password or filename.");
        msgBox.exec();
        return;
    }
    ret_msg = start(cryptoConfig);
    msgBox.setText(ret_msg);
    msgBox.exec();
    destroyConfig(cryptoConfig);
    destroyCString(ret_msg);
    m_ui->label->clear();
}
