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

#include "packet.h"
#include "sshout/api.h"

#include <QtCore/QByteArray>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <arpa/inet.h>

// Need to rewrite in a class

static quint32 length;
static QByteArray buffer;
static unsigned int ss;

SSHOUTGetPacketState sshout_get_packet(QIODevice *d, QByteArray *out_buffer) {
  // quint32 length;
  // QByteArray buffer;
  if (buffer.isEmpty()) {
    QDataStream in(&buffer, QIODevice::ReadOnly);

    buffer.resize(sizeof(struct sshout_api_packet));
    qint64 s = d->read(buffer.data(), sizeof(struct sshout_api_packet));
    if (s < 0) {
      *out_buffer = d->errorString().toLocal8Bit();
      qWarning("sshout_get_packet: read error: %s", out_buffer->data());
      buffer.clear();
      return SSHOUT_GET_PACKET_READ_ERROR;
    }
    if (s != sizeof(struct sshout_api_packet)) {
      qWarning("sshout_get_packet: short read (got %d byte(s))", (int)s);
      buffer.clear();
      return SSHOUT_GET_PACKET_SHORT_READ;
    }

    in >> length;
    length = ntohl(length);
    if (length < 1) {
      buffer.clear();
      return SSHOUT_GET_PACKET_TOO_SHORT;
    }
    if (length > SSHOUT_API_PACKET_MAX_LENGTH) {
      qWarning("sshout_get_packet: packet too long (%u bytes)",
               (unsigned int)length);
      buffer.clear();
      return SSHOUT_GET_PACKET_TOO_LONG;
    }
    buffer.resize(length);
    ss = 0;
  }
  while (ss < length) {
    int s = d->read(buffer.data() + ss, length - ss);
    if (s < 0) {
      *out_buffer = d->errorString().toLocal8Bit();
      qWarning("sshout_get_packet: read error: %s", out_buffer->data());
      buffer.clear();
      return SSHOUT_GET_PACKET_READ_ERROR;
    }
    if (!s)
      return SSHOUT_GET_PACKET_INCOMPLETE;
    ss += s;
  }
  *out_buffer = buffer;
  buffer.clear();
  return SSHOUT_GET_PACKET_SUCCESS;
}
