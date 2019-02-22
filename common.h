#ifndef COMMON_H
#define COMMON_H

#include <QtCore/qglobal.h>

#if !defined Q_OS_WIN || defined Q_OS_WINCE
#define DEFAULT_SSH_PROGRAM_PATH "/usr/bin/ssh"
#else
#define DEFAULT_SSH_PROGRAM_PATH "C:/Windows/System32/OpenSSH/ssh.exe"
#endif
#define DEFAULT_SSH_USER_NAME "sshout"
#define PROJECT_PAGE_URL "https://sourceforge.net/projects/sshout/"

#endif // COMMON_H
