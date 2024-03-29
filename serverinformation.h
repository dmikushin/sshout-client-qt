/* SSHOUT Client
 * Copyright 2015-2023 Rivoreo
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SERVERINFORMATION_H
#define SERVERINFORMATION_H

#include <QtCore/qglobal.h>
#include <QtCore/QDataStream>
#include <QtCore/QMetaType>
#include <QtCore/QString>

struct ServerInformation {
	QString host;
	quint16 port;
	QString identity_file;
};
Q_DECLARE_METATYPE(ServerInformation)


static inline QDataStream &operator<<(QDataStream &out, const ServerInformation &info) {
	return out << info.host << info.port << info.identity_file;
}

static inline QDataStream &operator>>(QDataStream &in, ServerInformation &info) {
	in >> info.host;
	in >> info.port;
	in >> info.identity_file;
	return in;
}

static inline bool operator==(const ServerInformation &v1, const ServerInformation &v2) {
	return v1.host == v2.host && v1.port == v2.port && v1.identity_file == v2.identity_file;
}

#endif // SERVERINFORMATION_H
