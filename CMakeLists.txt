cmake_minimum_required(VERSION 3.5)

project(sshout-qt)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets Sql REQUIRED)

set(SOURCES
    main.cpp
    connectionwindow.cpp
    settingsdialog.cpp
    mainwindow.cpp
    sshclient.cpp
    externalsshclient.cpp
    packet.cpp
    messagelog.cpp
)

set(HEADERS
    connectionwindow.h
    settingsdialog.h
    mainwindow.h
    serverinformation.h
    sshclient.h
    externalsshclient.h
    common.h
    packet.h
    messagelog.h
)

set(FORMS
    connectionwindow.ui
    settingsdialog.ui
    mainwindow.ui
)

set(RESOURCES
    icons.qrc
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${FORMS} ${RESOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Sql)
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-Wno-empty-body -Wno-write-strings")

set(TRANSLATIONS translations/sshout.zh-cn.ts)
set(CODECFORTR UTF-8)
