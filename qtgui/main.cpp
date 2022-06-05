#include "mainwindow.h"
#include <QApplication>
#include <QStyleFactory>
#include <QProcess>

MainWindow *gMainWindow;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationName("Cryptyrust");
    a.setApplicationVersion("2.0.0");
    a.setStyle(QStyleFactory::create("Fusion"));
    MainWindow w;
    gMainWindow = &w;
    w.show();
    int currentExitCode = a.exec();
    if (currentExitCode == -123456789) {
        QProcess::startDetached(qApp->applicationFilePath(), QStringList());
        return 0;
    }
    return currentExitCode;
}
