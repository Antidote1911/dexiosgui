#pragma once

#include <QMainWindow>
#include <memory>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

  public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void updateProgress(int);
    void restartApp();

  private slots:
    void slot_menuAbout();
    void configuration();
    void savePreferences();
    void slot_Open();
    void reboot();

  protected:
    void closeEvent(QCloseEvent *event) Q_DECL_OVERRIDE;

  private:
    const std::unique_ptr<Ui::MainWindow> m_ui;
    void applyTheme();
    void loadPreferences();
    void initViewMenu();
    void* cryptoConfig{};
    char* ret_msg{};
};

extern MainWindow *gMainWindow;
