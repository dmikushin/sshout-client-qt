/* SSHOUT Client
 * Copyright 2015-2023 Rivoreo
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#include "connectionwindow.h"
#include "ui_connectionwindow.h"
#include "serverinformation.h"
#include "settingsdialog.h"
#include "mainwindow.h"
#if QT_VERSION < 0x050000
#include <QtGui/QCompleter>
#include <QtGui/QFileDialog>
#include <QtGui/QMessageBox>
#else
#include <QtWidgets/QCompleter>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#endif
#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QSettings>
#include <QtCore/QList>
#include <QtCore/QDebug>

ConnectionWindow::ConnectionWindow(QWidget *parent, QSettings *config) :
	QDialog(parent),
	ui(new Ui::ConnectionWindow)
{
	ui->setupUi(this);
	QCompleter *completer = new QCompleter(this);
	completer->setCompletionMode(QCompleter::PopupCompletion);
	ui->remote_host_comboBox->setCompleter(completer);
	this->config = config;
	server_list = config->value("ServerList").toList();
	if(!server_list.isEmpty()) {
		foreach(const QVariant &i, server_list) {
			const QString &host = i.value<ServerInformation>().host;
			ui->remote_host_comboBox->addItem(host);
		}
		int index = config->value("LastServerIndex", 0).toInt();
		if(index < 0 || index >= server_list.count()) index = 0;
		const ServerInformation &info = server_list[index].value<ServerInformation>();
		ui->remote_host_comboBox->setCurrentIndex(index);
		ui->remote_port_lineEdit->setText(QString::number(info.port));
		ui->identity_file_lineEdit->setText(info.identity_file);
	}
	remote_host_name_change_event(ui->remote_host_comboBox->currentText());
	ui->checkBox_auto_connect->setChecked(config->value("AutoConnect", false).toBool());
}

ConnectionWindow::~ConnectionWindow()
{
	delete ui;
}

static QString ssh_config_dir() {
#ifdef Q_OS_WINCE
	return QApplication::applicationDirPath();
#else
	return QDir::homePath() + "/.ssh";
#endif
}

void ConnectionWindow::browse_identity_file() {
	QFileDialog d(this, tr("Choose the identity file"), ssh_config_dir());
	d.setAcceptMode(QFileDialog::AcceptOpen);
	d.setFileMode(QFileDialog::ExistingFile);
	d.setOption(QFileDialog::DontUseNativeDialog);
	if(d.exec()) {
		ui->identity_file_lineEdit->setText(d.selectedFiles()[0]);
	}
}

void ConnectionWindow::change_settings() {
	SettingsDialog d(this, config);
	d.set_current_tab(0);
	d.exec();
}

void ConnectionWindow::closeEvent(QCloseEvent *e) {
	qDebug("function: ConnectionWindow::closeEvent(%p)", e);
}

void ConnectionWindow::start_main_window() {
	qDebug("slot: ConnectionWindow::start_main_window()");
	const QString &host = ui->remote_host_comboBox->currentText();
	if(host.isEmpty()) {
		QMessageBox::critical(this, tr("Check Server Information"), tr("Host name cannot be empty"));
		return;
	}
	qint16 port = -1;
	const QString &port_str = ui->remote_port_lineEdit->text();
	if(!port_str.isEmpty()) {
		bool ok;
		port = port_str.toUInt(&ok);
		if(!ok) {
			QMessageBox::critical(this, tr("Check Server Information"), tr("Invalid port number"));
			return;
		}
	}
	const QString &identity_file = ui->identity_file_lineEdit->text();

	bool found = false;
	foreach(const QVariant &i, server_list) {
		ServerInformation info = i.value<ServerInformation>();
		if(info.host == host) {
			if(info.port == port && info.identity_file == identity_file) found = 1;
			else server_list.removeOne(i);
			break;
		}
	}
	if(!found) {
		if(identity_file.isEmpty()) {
			int answer = QMessageBox::warning(this,
				tr("Check Server Information"),
				tr("Identity file isn't set. Are you sure this is correct?"),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
			if(answer != QMessageBox::Yes) return;
		}
		ServerInformation info;
		info.host = host;
		info.port = port;
		info.identity_file = identity_file;
		QVariant v = QVariant::fromValue<ServerInformation>(info);
		server_list << v;
		config->setValue("ServerList", server_list);
	}
	int index = ui->remote_host_comboBox->currentIndex();
	if(index >= 0) config->setValue("LastServerIndex", index);
	config->setValue("AutoConnect", ui->checkBox_auto_connect->isChecked());
	hide();
	MainWindow *w = new MainWindow(NULL, config, host, port, identity_file);
	w->setAttribute(Qt::WA_DeleteOnClose);
	w->connect_ssh();
	w->show();
	accept();
}

void ConnectionWindow::remote_host_name_change_event(int index) {
	if(index < 0 || index >= server_list.count()) return;
	ServerInformation info = server_list[index].value<ServerInformation>();
	if(ui->remote_host_comboBox->currentText() != info.host) return;
	ui->remote_port_lineEdit->setText(QString::number(info.port));
	ui->identity_file_lineEdit->setText(info.identity_file);
}

void ConnectionWindow::remote_host_name_change_event(QString host_name) {
	ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!host_name.isEmpty());
}
