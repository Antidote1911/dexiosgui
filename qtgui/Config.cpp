/*
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
 *  Copyright (C) 2011 Felix Geyer <debfx@fobos.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Config.h"

#include <QCoreApplication>
#include <QDir>
#include <QHash>
#include <QSettings>
#include <QSize>
#include <QStandardPaths>
#include <QTemporaryFile>

#define CONFIG_VERSION 1
#define QS QStringLiteral

enum ConfigType {
    Local,
    Roaming
};

struct ConfigDirective {
    QString name;
    ConfigType type;
    QVariant defaultValue;
};

// clang-format off

/**
 * Map of legal config values, their type and default value.
 */
static const QHash<Config::ConfigKey, ConfigDirective> configStrings = {
    //cryptyrust
    {Config::GUI_ApplicationTheme, {QS("GUI/ApplicationTheme"), Roaming, QS("classic")}},

    {Config::GUI_MainWindowGeometry, {QS("GUI/MainWindowGeometry"), Local, {}}},
    {Config::GUI_MainWindowState, {QS("GUI/MainWindowState"), Local, {}}},

    {Config::CRYPTO_Strength, {QS("CRYPTO/argonMemory"), Roaming, 0}},
    {Config::CRYPTO_algorithm, {QS("CRYPTO/cryptoAlgo"), Roaming, 0}},

    };

// clang-format on

QPointer<Config> Config::m_instance(nullptr);

QVariant Config::get(ConfigKey key)
{
    auto cfg          = configStrings[key];
    auto defaultValue = configStrings[key].defaultValue;
    if (m_localSettings && cfg.type == Local) {
        return m_localSettings->value(cfg.name, defaultValue);
    }
    return m_settings->value(cfg.name, defaultValue);
}

bool Config::hasAccessError()
{
    return m_settings->status() & QSettings::AccessError;
}

QString Config::getFileName()
{
    return m_settings->fileName();
}

void Config::set(ConfigKey key, const QVariant& value)
{
    if (get(key) == value) {
        return;
    }

    auto cfg = configStrings[key];
    if (cfg.type == Local && m_localSettings) {
        m_localSettings->setValue(cfg.name, value);
    }
    else {
        m_settings->setValue(cfg.name, value);
    }

    emit changed(key);
}

void Config::remove(ConfigKey key)
{
    auto cfg = configStrings[key];
    if (cfg.type == Local && m_localSettings) {
        m_localSettings->remove(cfg.name);
    }
    else {
        m_settings->remove(cfg.name);
    }

    emit changed(key);
}

/**
 * Sync configuration with persistent storage.
 *
 * Usually, you don't need to call this method manually, but if you are writing
 * configurations after an emitted \link QCoreApplication::aboutToQuit() signal,
 * use it to guarantee your config values are persisted.
 */
void Config::sync()
{
    m_settings->sync();
    if (m_localSettings) {
        m_localSettings->sync();
    }
}

void Config::resetToDefaults()
{
    m_settings->clear();
    if (m_localSettings) {
        m_localSettings->clear();
    }
}



Config::Config(QObject* parent)
    : QObject(parent)
{
    // Check if we are running in portable mode, if so store the config files local to the app
    auto portablePath = QCoreApplication::applicationDirPath().append("/%1");
    if (QFile::exists(portablePath.arg(".portable"))) {
        init(portablePath.arg("config/dexios.ini"), portablePath.arg("config/dexios_local.ini"));
        return;
    }

    QString configPath;
    QString localConfigPath;

#if defined(Q_OS_WIN)
    configPath      = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    localConfigPath = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
#elif defined(Q_OS_MACOS)
    configPath      = QDir::fromNativeSeparators(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    localConfigPath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
#else
    configPath      = QDir::fromNativeSeparators(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation));
    localConfigPath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
#endif

    configPath += "/dexios";
    localConfigPath += "/dexios";

#ifdef QT_DEBUG
    configPath += "_debug";
    localConfigPath += "_debug";
#endif

    configPath += ".ini";
    localConfigPath += ".ini";

    init(QDir::toNativeSeparators(configPath), QDir::toNativeSeparators(localConfigPath));
}

Config::~Config()
{
}

void Config::init(const QString& configFileName, const QString& localConfigFileName)
{
    // Upgrade from previous KeePassXC version which stores its config
    // in AppData/Local on Windows instead of AppData/Roaming.
    // Move file to correct location before continuing.
    if (!localConfigFileName.isEmpty() && QFile::exists(localConfigFileName) && !QFile::exists(configFileName)) {
        QDir().mkpath(QFileInfo(configFileName).absolutePath());
        QFile::copy(localConfigFileName, configFileName);
        QFile::remove(localConfigFileName);
        QDir().rmdir(QFileInfo(localConfigFileName).absolutePath());
    }

    m_settings.reset(new QSettings(configFileName, QSettings::IniFormat));
    if (!localConfigFileName.isEmpty() && configFileName != localConfigFileName) {
        m_localSettings.reset(new QSettings(localConfigFileName, QSettings::IniFormat));
    }

    connect(qApp, &QCoreApplication::aboutToQuit, this, &Config::sync);
}

Config* Config::instance()
{
    if (!m_instance) {
        m_instance = new Config(qApp);
    }

    return m_instance;
}

#undef QS
