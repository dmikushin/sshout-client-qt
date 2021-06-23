/* Secure Shout Host Oriented Unified Talk
 * Copyright 2015-2021 Rivoreo
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

#include "messagelog.h"
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtCore/QDateTime>
#include <QtCore/QVariant>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QCoreApplication>
#include <signal.h>
#ifdef Q_OS_BSD4
#include <sys/sysctl.h>
#if defined Q_OS_DARWIN && MAC_OS_X_VERSION_MIN_REQUIRED >= 1050
#include <libproc.h>
#define HAVE_PROC_PIDPATH
#endif
#endif
#ifdef Q_OS_WIN
#include <windows.h>
#endif

MessageLog::MessageLog()  {
	//database = new QSqlDatabase;
	//QSQLiteDriver *driver = new QSQLiteDriver;
	//database = QSqlDatabase::addDatabase(driver);
	database = QSqlDatabase::addDatabase("QSQLITE");
}

static bool is_another_instance(int pid) {
#ifndef Q_OS_WIN
	if(pid < 1) return false;
	if(kill(pid, 0) < 0) return false;
#else
	HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	// The Windows API design is shit!
	if(handle != INVALID_HANDLE_VALUE && handle) {
		CloseHandle(handle);
		return false;
	}
#endif

	QString self_path = QCoreApplication::applicationFilePath();
	QString path;
#ifdef Q_OS_SOLARIS
	path = QFile::symLinkTarget(QString("/proc/%1/path/a.out").arg(pid));
#elif defined Q_OS_LINUX
	if(self_path.endsWith(" (deleted)")) self_path.chop(10);
	path = QFile::symLinkTarget(QString("/proc/%1/exe").arg(pid));
	if(path.endsWith(" (deleted)")) path.chop(10);
#elif defined Q_OS_BSD4
#ifdef Q_OS_DARWIN
#define ki_comm kp_proc.p_comm
#endif
	size_t len;
	int mib[] = { CTL_KERN, KERN_PROC, 0, pid };
#ifdef KERN_PROC_PATHNAME
	char buffer[PATH_MAX + 1];
	len = sizeof buffer;
	mib[2] = KERN_PROC_PATHNAME;
	if(sysctl(mib, 4, buffer, &len, NULL, 0) == 0 && len) {
		path = QString::fromLocal8Bit(buffer, len - 1);
	}
#elif defined Q_OS_DARWIN && defined HAVE_PROC_PIDPATH
	char buffer[PATH_MAX + 1];
	if(proc_pidpath(pid, buffer, sizeof buffer) == 0) {
		path = QString::fromLocal8Bit(buffer);
	}
#endif

	if(path.isEmpty()) {
		struct kinfo_proc proc;
		len = sizeof proc;
		mib[2] = KERN_PROC_PID;
		if(sysctl(mib, 4, &proc, &len, NULL, 0) == 0) {
			path = QString::fromLocal8Bit(proc.ki_comm);
		}
	}
#endif
	if(!path.isEmpty() && !self_path.isEmpty() && QFileInfo(path).fileName() != QFileInfo(self_path).fileName()) {
		return false;
	}

	return true;
}

bool MessageLog::open(const QString &path) {
	if(!database.isValid()) return false;
	database.setDatabaseName(path);
	//qDebug("is open ? %d", database.isOpen());
	if(database.isOpen()) return false;
	QByteArray lock_path_ba = path.toLocal8Bit();
	lock_file = new QFile(QString("%1.lock").arg(path));
	if(lock_file->exists()) {
		if(!lock_file->open(QFile::ReadOnly)) {
			qWarning("MessageLog::open: lock file '%s' exist but can't open", lock_path_ba.data());
			return false;
		}
		QByteArray content = lock_file->readLine();
		lock_file->close();
		if(!content.isEmpty()) {
			int pid = content.toInt();
			if(is_another_instance(pid)) {
				qWarning("MessageLog::open: database file is locked by process %d via lock file '%s'", pid, lock_path_ba.data());
				return false;
			}
		}
		//lock_file->remove();
	}
	if(!lock_file->open(QFile::WriteOnly | QFile::Truncate)) {
		qWarning("MessageLog::open: cannot open lock file '%s'", lock_path_ba.data());
		return false;
	}
	if(lock_file->write(QByteArray::number(QCoreApplication::applicationPid())) < 0) {
		QByteArray error_msg = lock_file->errorString().toLocal8Bit();
		qWarning("MessageLog::open: cannot write to lock file '%s', %s", lock_path_ba.data(), error_msg.data());
		lock_file->close();
		return false;
	}
	lock_file->close();
	QFile db_file(path);
	bool need_chmod = !db_file.exists();
	if(!database.open()) return false;
	if(need_chmod) db_file.setPermissions(QFile::ReadUser | QFile::WriteUser);
	QString sql_create_table("CREATE TABLE IF NOT EXISTS messages ("
				 "id INTEGER PRIMARY KEY AUTOINCREMENT,"
				 "receive_time DATETIME,"
				 "time DATETIME,"
				 "from_user CHAR(32),"
				 "to_user CHAR(32),"
				 "type INT8,"
				 "message TEXT );");
	if(!QSqlQuery(sql_create_table, database).exec()) {
		QByteArray ba = path.toLocal8Bit();
		qWarning("MessageLog::open: failed to run create table SQL in database %s, giving up open", ba.data());
		database.close();
		return false;
	}
	return true;
}

void MessageLog::close() {
	if(!database.isOpen()) return;
	database.close();
	lock_file->remove();
}

bool MessageLog::append_message(const QDateTime &dt, const QString &from_user, const QString &to_user, quint8 type, const QByteArray &message) {
	QSqlQuery query(database);
	query.prepare("INSERT INTO messages (receive_time,time,from_user,to_user,type,message) VALUES (?,?,?,?,?,?);");
	query.bindValue(0, QDateTime::currentDateTime());
	query.bindValue(1, dt);
	query.bindValue(2, from_user);
	query.bindValue(3, to_user);
	query.bindValue(4, type);
	query.bindValue(5, message);
	return query.exec();
}
