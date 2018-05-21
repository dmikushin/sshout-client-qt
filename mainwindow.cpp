/* Secure Shout Host Oriented Unified Talk
 * Copyright 2015-2018 Rivoreo
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

#include "common.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#ifdef HAVE_OPENSSH_LIBRARY
#include "internalsshclient.h"
#endif
#include "externalsshclient.h"
#include "settingsdialog.h"
#include "connectionwindow.h"
#include "sshout/api.h"
#include "packet.h"
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtCore/QDataStream>
//#include <QtCore/QDateTime>
#include <QtCore/QTime>
#include <QtCore/QBuffer>
#if QT_VERSION < 0x050000
#include <QtGui/QKeyEvent>
#include <QtGui/QListWidgetItem>
#include <QtGui/QFileDialog>
#include <QtGui/QMessageBox>
#include <QtGui/QImage>
#include <QtGui/QScrollBar>
#include <QtGui/QDesktopServices>
#else
#include <QtWidgets/QListWidgetItem>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QImage>
#endif
#include <QtCore/QTemporaryFile>
#include <QtCore/QUrl>
//#include <QtGui/QRubberBand>
#include <stdio.h>
#include <QtCore/QDebug>

#define appendPlainText append

extern QString config_dir();

MainWindow::MainWindow(QWidget *parent, QSettings *config, const QString &host, quint16 port, const QString &identify_file) :
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	ui->setupUi(this);
	this->config = config;
	//setMouseTracking(true);
#ifdef HAVE_OPENSSH_LIBRARY
	use_internal_ssh_library = config->value("UseInternalSSHLibrary", false).toBool();
	if(use_internal_ssh_library) ssh_client = new InternalSSHClient(this);
	else
#endif
	ssh_client = new ExternalSSHClient(this, config->value("SSHProgramPath", DEFAULT_SSH_PROGRAM_PATH).toString());
#ifndef HAVE_OPENSSH_LIBRARY
	use_internal_ssh_library = false;
#endif
	ssh_client->set_identify_file(identify_file);
	this->host = host;
	this->port = port;
	connect(ssh_client, SIGNAL(state_changed(SSHClient::SSHState)), SLOT(ssh_state_change(SSHClient::SSHState)));
	connect(ssh_client, SIGNAL(readyRead()), SLOT(read_ssh()));
	if(!use_internal_ssh_library) {
		ExternalSSHClient *extern_ssh_client = (ExternalSSHClient *)ssh_client;
		extern_ssh_client->register_ready_read_stderr_slot(this, SLOT(read_ssh_stderr()));
		QString args = config->value("SSHArgs").toString();
		if(!args.isEmpty()) extern_ssh_client->set_extra_args(args.split(' '));
	}
	send_message_on_enter = config->value("UseEnterToSendMessage", true).toBool();
	ui->action_press_enter_to_send_message->setChecked(send_message_on_enter);
	ui->action_use_html_for_sending_messages->setChecked(config->value("UseHTMLForSendingMessages", false).toBool());
	ui->textEdit_message_to_send->installEventFilter(this);
	control_key_pressed = false;
	ignore_key_event = false;
	need_reconnect = true;
	bool show_user_list = config->value("ShowUserList", true).toBool();
	ui->dockWidget_online_list->setVisible(show_user_list);
	ui->action_show_online_users->setChecked(show_user_list);
	if(show_user_list) {
		QVariant v = config->value("UserListWindowSize");
		if(!v.isNull()) ui->dockWidget_online_list->resize(v.toSize());
	}
	if(config->value("WindowMaximized", false).toBool()) showMaximized();
	else {
		QVariant v = config->value("WindowSize");
		if(!v.isNull()) resize(v.toSize());
	}
	ui->textEdit_message_to_send->setFocus();
	data_stream = new QDataStream(ssh_client);
	//data_stream->setByteOrder(QDataStream::BigEndian);
	timer = new QTimer(this);
	timer->setInterval(60000);
	connect(timer, SIGNAL(timeout()), SLOT(send_request_online_users()));
	//cache_file_allocator = new QTemporaryFile(this);
	//cache_file_allocator->setAutoRemove(false);
	cache_dir = new QDir(QString("%1/cache/%2").arg(config_dir()).arg(host));
	if(!cache_dir->mkpath(".")) {
		qWarning("Cannot create cache directory");
		QMessageBox::warning(this, QString(), tr("Failed to create cache directory '%1'").arg(cache_dir->path()));
	}
	apply_chat_area_config();
	connect_ssh();
}

MainWindow::~MainWindow()
{
	delete ui;
	delete ssh_client;
	delete data_stream;
	delete timer;
}

void MainWindow::keyPressEvent(QKeyEvent *e) {
	//qDebug("function: MainWindow::keyPressEvent(%p)", e);
	if(focusWidget() == ui->textEdit_message_to_send) {
		bool show_tip = true;
		int key = e->key();
		//qDebug("key = 0x%x", key);
		switch(key) {
			case Qt::Key_Control:
				show_tip = false;
				control_key_pressed = true;
				break;
			case Qt::Key_Enter:
			case Qt::Key_Return:
				show_tip = false;
				if(send_message_on_enter) {
					if(control_key_pressed) ui->textEdit_message_to_send->insertPlainText("\n");
					else send_message();
					ignore_key_event = true;
				} else if(control_key_pressed) {
					send_message();
					ignore_key_event = true;
				}
				break;
			case Qt::Key_Backspace:
				show_tip = false;
				break;
		}
		if(show_tip) ui->statusbar->showMessage(tr("Press %1 to send").arg(send_message_on_enter ? tr("Enter") : tr("Ctrl-Enter")), 2000);
	}
}

void MainWindow::keyReleaseEvent(QKeyEvent *e) {
	//qDebug("function: MainWindow::keyReleaseEvent(%p)", e);
	if(focusWidget() == ui->textEdit_message_to_send) {
		int key = e->key();
		//qDebug("key = 0x%x", key);
		if(key == Qt::Key_Control) control_key_pressed = false;
	}
}

bool MainWindow::eventFilter(QObject *o, QEvent *e) {
	//qDebug("function: MainWindow::eventFilter(%p, %p)", o, e);
	if(o != ui->textEdit_message_to_send) return QObject::eventFilter(o, e);
	if(e->type() != QEvent::KeyPress) return QObject::eventFilter(o, e);
	keyPressEvent(static_cast<QKeyEvent *>(e));
	if(!ignore_key_event) return false;
	ignore_key_event = false;
	return true;
}

void MainWindow::save_ui_layout() {
	bool show_user_list = ui->dockWidget_online_list->isVisible();
	config->setValue("ShowUserList", show_user_list);
	if(isMaximized()) config->setValue("WindowMaximized", true);
	else config->setValue("WindowSize", size());
	if(show_user_list) {
		config->setValue("UserListWindowSize", ui->dockWidget_online_list->size());
	}
}

void MainWindow::closeEvent(QCloseEvent *e) {
	need_reconnect = false;
	ssh_client->disconnect();
	save_ui_layout();
	e->accept();
}

void MainWindow::connect_ssh() {
	if(!ssh_client->connect(host, port, DEFAULT_SSH_USER_NAME, "api")) {
		ui->statusbar->showMessage(tr("Cannot connect"), 10000);
	}
}

QString MainWindow::create_random_hex_string(int len) {
	//char buffer[len * 2];
	QByteArray buffer;
	//buffer.resize(len * 2);
	//int i = 0;
	//while(i < len) {
	while(len-- > 0) {
		//QString::number(qrand() & 0xff, 0x10);
		char n = qrand() & 0xff;
		buffer.append(QByteArray(&n, 1).toHex());
	}
	return QString::fromLatin1(buffer);
}

void MainWindow::print_image(const QByteArray &data) {
	QImage image;
	if(!image.loadFromData(data, "JPEG")) {
		ui->chat_area->appendPlainText(tr("[Failed to load image]") + "\n");
		return;
	}

#if 0
	QString file_name = create_random_hex_string(16) + ".jpg";
	//image.save(QString("%1/%2").arg(config_dir()).arg(file_na))
	QUrl url(cache_dir->filePath(file_name));
#if 0
	if(!image.save(url.toString(QUrl::RemoveScheme))) {
#else
	QFile image_file(url.toString(QUrl.RemoveScheme));
	if(image_file.open(QIODevice::WriteOnly)) {
#endif
		ui->chat_area->appendPlainText(tr("[Failed to save image]"));
		return;
	}
#else
	QString image_file_name;
	QFile image_file;
	do {
		image_file_name = create_random_hex_string(16) + ".jpg";
		image_file.setFileName(cache_dir->filePath(image_file_name));
	} while(image_file.exists());
	if(!image_file.open(QIODevice::WriteOnly)) {
		ui->chat_area->appendPlainText(tr("[Failed to save image, %1]").arg(image_file.errorString()));
		return;
	}
	if(image_file.write(data) < data.length()) {
		ui->chat_area->appendPlainText(tr("[File %1 short write]").arg(image_file_name));
		image_file.close();
		return;
	}
	image_file.close();
	QUrl url(image_file.fileName());
	url.setScheme("file");
	qDebug() << url;
#endif
	QTextDocument *doc = ui->chat_area->document();
	doc->addResource(QTextDocument::ImageResource, url, image);
	QTextCursor cursor = ui->chat_area->textCursor();
	//cursor.insertImage(image);
	QTextImageFormat image_format;
	image_format.setWidth(image.width());
	image_format.setHeight(image.height());
	image_format.setName(url.toString());
	cursor.movePosition(QTextCursor::End);
	cursor.insertImage(image_format);
	ui->chat_area->setTextCursor(cursor);
}

void MainWindow::print_message(const QTime &time, const QString &msg_from, const QString &msg_to, quint8 msg_type, const QByteArray &message) {
	//QDateTime dt = QDateTime::currentDateTime();
	//QTime t = QTime::currentTime();
	QString tag = (msg_to.isEmpty() || msg_to == QString("GLOBAL")) ?
		QString("%1 %2").arg(msg_from).arg(time.toString("H:mm:ss")) :
		tr("%1 to %2 %3").arg(msg_from).arg(msg_to).arg(time.toString("H:mm:ss"));
	qDebug() << QString::fromUtf8(message);
	qDebug() << tag;
	QScrollBar *chat_area_scroll_bar = ui->chat_area->verticalScrollBar();
	bool should_scroll = chat_area_scroll_bar->value() >= chat_area_scroll_bar->maximum();
	//ui->chat_area->append(QString());
	QTextCursor cursor = ui->chat_area->textCursor();
	cursor.movePosition(QTextCursor::End);
	ui->chat_area->setTextCursor(cursor);
	ui->chat_area->insertPlainText("\n");
	switch(msg_type) {
		case SSHOUT_API_MESSAGE_TYPE_PLAIN:
			ui->chat_area->insertPlainText(tag + "\n" + QString::fromUtf8(message));
			break;
		case SSHOUT_API_MESSAGE_TYPE_RICH:
			ui->chat_area->insertPlainText(tag + "\n");
			ui->chat_area->insertHtml(QString::fromUtf8(message));
			break;
		case SSHOUT_API_MESSAGE_TYPE_IMAGE:
			ui->chat_area->insertPlainText(tag + "\n");
			print_image(message);
			break;
	}
	apply_chat_area_config();
	ui->chat_area->append(QString());
	if(should_scroll) chat_area_scroll_bar->setValue(chat_area_scroll_bar->maximum());
	ui->chat_area->horizontalScrollBar()->setValue(0);
}

void MainWindow::send_hello() {
	quint32 length = 1 + 6 + 2;
	quint8 type = SSHOUT_API_HELLO;
	quint16 version = 1;
	*data_stream << length;
	*data_stream << type;
	data_stream->writeRawData("SSHOUT", 6);
	*data_stream << version;
	//ssh_client->write("Test");
}

void MainWindow::send_message(const QString &to_user, quint8 message_type, const QByteArray &message) {
	if(!ssh_client->is_connected()) {
		ui->statusbar->showMessage(tr("Cannot send message, server is not connected"));
		return;
	}
	QByteArray to_user_bytes = to_user.toUtf8();
	if(to_user_bytes.length() > 32) {
		qWarning("MainWindow::send_message: user name too long");
		return;
	}
	quint8 to_user_len = to_user_bytes.length();
	quint32 message_len = message.length();
	quint32 packet_length = 1 + 1 + to_user_len + 1 + 4 + message_len;
	quint8 packet_type = SSHOUT_API_SEND_MESSAGE;
	*data_stream << packet_length;
	*data_stream << packet_type;
	*data_stream << to_user_len;
	data_stream->writeRawData(to_user_bytes.data(), to_user_len);
	*data_stream << message_type;
	*data_stream << message_len;
	data_stream->writeRawData(message.data(), message_len);

}

void MainWindow::send_message() {
	qDebug("slot: MainWindow::send_message()");
	bool use_html = ui->action_use_html_for_sending_messages->isChecked();
	QString message = use_html ? ui->textEdit_message_to_send->toHtml() : ui->textEdit_message_to_send->toPlainText();
	if(message.isEmpty()) return;

	QByteArray message_bytes = message.toUtf8();

	ui->statusbar->showMessage(tr("Sending message"), 1000);
	// TODO: get user name from current selection of user list
	//QString ui->listWidget_online_users->currentItem()
	send_message("GLOBAL", use_html ? SSHOUT_API_MESSAGE_TYPE_RICH : SSHOUT_API_MESSAGE_TYPE_PLAIN, message_bytes);

	ui->textEdit_message_to_send->clear();
}

void MainWindow::add_user_item(const QString &user_name, QList<UserIdAndHostName> *logins) {
	QListWidgetItem *item;
	QList<QListWidgetItem *> orig_items = ui->listWidget_online_users->findItems(user_name, Qt::MatchFixedString | Qt::MatchCaseSensitive);
	int exists = orig_items.length();
	if(exists) {
		Q_ASSERT(exists == 1);
		item = orig_items[0];
	} else {
		item = new QListWidgetItem(user_name);
		item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
	}
	item->setData((int)Qt::UserRole, QVariant::fromValue((void *)logins));
	if(!exists) ui->listWidget_online_users->addItem(item);
}

void MainWindow::remove_offline_user_items(const QSet<QString> &keep_set) {
	QList<QListWidgetItem *> items = ui->listWidget_online_users->findItems("*", Qt::MatchWildcard);
	//qDebug() << items;
	foreach(QListWidgetItem *i, items) {
		if(keep_set.contains(i->text())) continue;
		delete (QList<UserIdAndHostName> *)i->data((int)Qt::UserRole).value<void *>();
		delete i;
	}
}

void MainWindow::update_user_list(const UserInfo *users, unsigned int count) {
	QSet<QString> user_set;
	QHash<QString, QList<UserIdAndHostName> > user_logins;
	for(unsigned int i=0; i<count; i++) {
		const UserInfo *p = users + i;
		user_set << p->user_name;
		user_logins[p->user_name] << (UserIdAndHostName){ p->id, p->host_name };
	}
	remove_offline_user_items(user_set);
	foreach(const QString &user, user_set) {
		add_user_item(user, new QList<UserIdAndHostName>(user_logins[user]));
	}
}

void MainWindow::send_request_online_users() {
	quint32 length = 1;
	quint8 type = SSHOUT_API_GET_ONLINE_USER;
	*data_stream << length;
	*data_stream << type;
}

void MainWindow::update_user_state(const QString &user, quint8 state) {
	ui->chat_area->appendPlainText(tr("%1 is %2\n").arg(user).arg(state ? tr("joined") : tr("leave")));
	if(state) {
		send_request_online_users();
		timer->start();
	} else {
		QList<QListWidgetItem *> items = ui->listWidget_online_users->findItems(user, Qt::MatchFixedString | Qt::MatchCaseSensitive);
		//qDebug() << items;
		if(items.isEmpty()) return;
		Q_ASSERT(items.count() == 1);
		delete (QList<UserIdAndHostName> *)items[0]->data((int)Qt::UserRole).value<void *>();
		delete items[0];
	}
}

void MainWindow::print_error(quint32 error_code, const QString &error_message) {
	qDebug("MainWindow::print_error(%u, const QString &)", (unsigned int)error_code);
	ui->chat_area->appendPlainText(tr("Error from server: %1").arg(error_message) + "\n");
}

void MainWindow::apply_chat_area_config() {
#if 0
	QVariant font_from_config = config->value("Text/DefaultFontFamily");
	//if(!font.isNull()) ui->chat_area->setCurrentFont(font.value<QFont>());
	QFont font = font_from_config.isNull() ? ui->chat_area->font() : font_from_config.value<QFont>();
	int font_size = config->value("Text/DefaultFontSize").toInt();
	if(font_size) font.setPointSize(font_size);
	ui->chat_area->setFont(font);
#else
	QString font_name = config->value("Text/DefaultFontFamily").toString();
	if(!font_name.isEmpty()) ui->chat_area->setFontFamily(font_name);
	int font_size = config->value("Text/DefaultFontSize").toInt();
	if(font_size > 0) ui->chat_area->setFontPointSize(font_size);
#endif
}

void MainWindow::ssh_state_change(SSHClient::SSHState state) {
	qDebug("slot: MainWindow::ssh_state_change(%d)", state);
	switch(state) {
		case SSHClient::DISCONNECTED:
			//ui->statusbar->showMessage(tr("Disconnected"));
			timer->stop();
			if(need_reconnect) QTimer::singleShot(10000, this, SLOT(connect_ssh()));
			break;
		case SSHClient::CONNECTIING:
			if(use_internal_ssh_library) ui->statusbar->showMessage(tr("Connecting"));
			break;
		case SSHClient::AUTHENTICATING:
			if(use_internal_ssh_library) ui->statusbar->showMessage(tr("Authenticating"));
			break;
		case SSHClient::AUTHENTICATED:
			ui->statusbar->showMessage(tr("Connected"));
			send_hello();
			break;
	}
}

void MainWindow::read_ssh() {
	qDebug("slot: MainWindow::read_ssh()");
	while(ssh_client->bytesAvailable() > 0) {
#if 0
		QByteArray data = sshout_get_packet(ssh_client);
		if(data.isEmpty()) {
			//ssh_client->disconnect();
			return;
		}
#else
		QByteArray data;
		switch(sshout_get_packet(ssh_client, &data)) {
			case SSHOUT_GET_PACKET_SUCCESS:
				break;
			case SSHOUT_GET_PACKET_INCOMPLETE:
				continue;
			case SSHOUT_GET_PACKET_READ_ERROR:
				ssh_client->disconnect();
				return;
			case SSHOUT_GET_PACKET_SHORT_READ:
				ssh_client->disconnect();
				return;
			case SSHOUT_GET_PACKET_TOO_LONG:
				ssh_client->disconnect();
				return;
			case SSHOUT_GET_PACKET_TOO_SHORT:
				ssh_client->disconnect();
				return;
		}
#endif
		QDataStream stream(&data, QIODevice::ReadOnly);
		quint8 packet_type;
		stream >> packet_type;
		switch(packet_type) {
			case SSHOUT_API_PASS:
				qDebug("SSHOUT_API_PASS received");
				if(data.mid(1, 6) != QString("SSHOUT")) {
					qWarning("Magic mismatch");
					ui->chat_area->appendPlainText(tr("Magic mismatch"));
					need_reconnect = false;
					ssh_client->disconnect();
					return;
				}
				stream.skipRawData(6);
				quint16 version;
				stream >> version;
				if(version != 1) {
					qWarning("Version mismatch (%hu != 1)", version);
					ui->chat_area->appendPlainText(tr("Version mismatch (%1 != 1)").arg(version));
					need_reconnect = false;
					ssh_client->disconnect();
					return;
				}
				send_request_online_users();
				timer->start();
				break;
			case SSHOUT_API_ONLINE_USERS_INFO:
				qDebug("SSHOUT_API_ONLINE_USERS_INFO received");
				{
					quint16 my_id;
					stream >> my_id;
					quint16 count;
					stream >> count;
					UserInfo users[count];
					unsigned int i = 0;
					//while(count-- > 0) {
					while(i < count) {
						quint16 id;
						quint8 user_name_len, host_name_len;
						stream >> id;
						stream >> user_name_len;
						char user_name[user_name_len];
						stream.readRawData(user_name, user_name_len);
						stream >> host_name_len;
						char host_name[host_name_len];
						stream.readRawData(host_name, host_name_len);
						UserInfo *p = users + i++;
						p->id = id;
						p->user_name = QString::fromUtf8(user_name, user_name_len);
						p->host_name = QString::fromUtf8(host_name, host_name_len);
					}
					update_user_list(users, count);
				}
				break;
			case SSHOUT_API_RECEIVE_MESSAGE:
				qDebug("SSHOUT_API_RECEIVE_MESSAGE received");
				{
					quint64 time;
					stream >> time;
					quint8 from_user_len;
					stream >> from_user_len;
					if(1 + 8 + 1 + from_user_len + 1 + 1 + 4 > data.length()) {
						qWarning("malformed SSHOUT_API_RECEIVE_MESSAGE packet: from_user_len %hhu too large", from_user_len);
						ssh_client->disconnect();
						return;
					}
					char from_user[from_user_len];
					stream.readRawData(from_user, from_user_len);
					quint8 to_user_len;
					stream >> to_user_len;
					if(1 + 8 + 1 + from_user_len + 1 + to_user_len + 1 + 4 > data.length()) {
						qWarning("malformed SSHOUT_API_RECEIVE_MESSAGE packet: to_user_len %hhu too large", to_user_len);
						ssh_client->disconnect();
						return;
					}
					char to_user[to_user_len];
					stream.readRawData(to_user, to_user_len);
					quint8 msg_type;
					stream >> msg_type;
					quint32 msg_len;
					stream >> msg_len;
					qDebug() << data.length() << time << from_user_len << to_user_len << msg_type;
					if(1 + 8 + 1 + (int)from_user_len + 1 + (int)to_user_len + 1 + 4 + (int)msg_len > data.length()) {
						qWarning("malformed SSHOUT_API_RECEIVE_MESSAGE packet: msg_len %hhu too large", msg_len);
						//ssh_client->disconnect();
						return;
					}
					qDebug() << msg_len;
					print_message(QDateTime::fromTime_t(time).time(),
						      QString::fromUtf8(from_user, from_user_len),
						      QString::fromUtf8(to_user, to_user_len),
						      msg_type,
						      data.mid(1 + 8 + 1 + from_user_len + 1 + to_user_len + 1 + 4, msg_len));
				}
				break;
			case SSHOUT_API_USER_STATE_CHANGE:
				qDebug("SSHOUT_API_USER_STATE_CHANGE received");
				{
					qDebug("length: %d", data.length());
					quint8 state;
					stream >> state;
					quint8 user_name_len;
					stream >> user_name_len;
					if(1 + 1 + 1 + (int)user_name_len > data.length()) {
						qWarning("malformed SSHOUT_API_USER_STATE_CHANGE packet: user_name_len %hhu too large", user_name_len);
						ssh_client->disconnect();
						return;
					}
					update_user_state(QString::fromUtf8(data.mid(3, user_name_len)), state);
				}
				break;
			case SSHOUT_API_ERROR:
				qDebug("SSHOUT_API_ERROR received");
				{
					quint32 error_code;
					stream >> error_code;
					quint32 error_msg_len;
					stream >> error_msg_len;
					if(1 + 4 + 4 + (int)error_msg_len > data.length()) {
						qWarning("malformed SSHOUT_API_ERROR packet: error_msg_len %hhu too large", error_msg_len);
						ssh_client->disconnect();
						return;
					}
					print_error(error_code, QString::fromUtf8(data.mid(9, error_msg_len)));
				}
				break;
			case SSHOUT_API_MOTD:
				qDebug("SSHOUT_API_MOTD received");
				quint32 length;
				stream >> length;
				if(length > (unsigned int)data.length() - 1 - 4) {
					qWarning("malformed packet: member size %u out of packet size %d", length, data.length());
					ssh_client->disconnect();
					return;
				}
				//if(data[5 + length - 1] == '\n') length--;
				if(data[5 + length - 1] != '\n') {
					data.append('\n');
					length++;
				}
				ui->chat_area->append(QString::fromUtf8(data.mid(5, length)));
				break;
		}
	}
}

void MainWindow::read_ssh_stderr() {
	//qDebug("slot: MainWindow::read_ssh_stderr()");
	if(use_internal_ssh_library) return;
	ExternalSSHClient *extern_ssh_client = (ExternalSSHClient *)ssh_client;
	while(extern_ssh_client->can_read_line_from_stderr()) {
		QByteArray data = extern_ssh_client->read_line_from_stderr();
		int len = data.count();
		if(!len) return;
		fputs(data.data(), stderr);
		if(data[len - 1] == '\n') data.resize(len - 1);
		ui->statusbar->showMessage(QString::fromLocal8Bit(data), 10000);
	}
}

void MainWindow::set_send_message_on_enter(bool v) {
	qDebug("slot: MainWindow::set_send_message_on_enter(%s)", v ? "true" : "false");
	send_message_on_enter = v;
	config->setValue("UseEnterToSendMessage", v);
}

void MainWindow::settings() {
	SettingsDialog d(this, config);
	if(!d.exec()) return;
	apply_chat_area_config();
}

void MainWindow::change_server() {
	ConnectionWindow *w = new ConnectionWindow(NULL, config);
	w->show();
	close();
}

void MainWindow::set_use_html(bool v) {
	config->setValue("UseHTMLForSendingMessages", v);
}

void MainWindow::send_image() {
	QFileDialog d(this, tr("Choose an image to upload"));
	d.setAcceptMode(QFileDialog::AcceptOpen);
	d.setFileMode(QFileDialog::ExistingFile);
	d.setOption(QFileDialog::DontUseNativeDialog);
	if(d.exec()) {
		QString path = d.selectedFiles()[0];
		qDebug() << path;
		QImage image(path);
		if(image.isNull()) {
			QMessageBox::critical(this, QString(), tr("Cannot load file '%1' as an image").arg(path));
			return;
		}
		QByteArray data;
		QBuffer buffer(&data, this);
		buffer.open(QIODevice::WriteOnly);
		if(!image.save(&buffer, "JPEG")) {
			QMessageBox::critical(this, QString(), tr("Cannot export the image as JPEG"));
			return;
		}
		buffer.close();
		send_message("GLOBAL", SSHOUT_API_MESSAGE_TYPE_IMAGE, data);
	}
}

void MainWindow::open_project_page() {
	QDesktopServices::openUrl(QUrl(PROJECT_PAGE_URL));
}

void MainWindow::show_about() {
	QMessageBox d(this);
	d.setWindowTitle(tr("About"));
	d.setText("<h3>Secure Shout Host Oriented Unified Talk</h3>Copyright 2018 Rivoreo<br/><br/>" +
		tr("This program is free software; you are free to change and redistribute it; see the source for copying conditions.") + "<br/>" +
		tr("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."));
	d.exec();
}
