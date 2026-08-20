# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# The Qt Widgets GUI library (lattica-qt). Mirrors Bitcoin Core's src/qt: a
# static latticaqt lib parsed for translatable strings and linked into the
# lattica-qt executable, which links lattica_core directly (no RPC). Sources
# are added here as they are ported, bottom-up.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS forms)
set(CMAKE_AUTORCC OFF)

# Icon/animation/font resources (res/, mapped to :/icons/* etc. by lattica.qrc).
qt6_add_resources(LATTICA_QRC lattica.qrc)

# Translations: lattica_locale.qrc bundles the .qm files that locale/CMakeLists.txt
# compiles from the .ts via lrelease into the binary dir, so the qrc is copied next
# to them (configure_file) and bundled from there (mapped to :/translations/<code>).
configure_file(lattica_locale.qrc lattica_locale.qrc USE_SOURCE_PERMISSIONS COPYONLY)
qt6_add_resources(LATTICA_LOCALE_QRC ${CMAKE_CURRENT_BINARY_DIR}/lattica_locale.qrc)

add_library(latticaqt STATIC EXCLUDE_FROM_ALL
  ${LATTICA_QRC}
  ${LATTICA_LOCALE_QRC}
  addresstablemodel.cpp
  addresstablemodel.h
  addressbookpage.cpp
  addressbookpage.h
  askpassphrasedialog.cpp
  askpassphrasedialog.h
  bantablemodel.cpp
  bantablemodel.h
  clientmodel.cpp
  clientmodel.h
  csvmodelwriter.cpp
  csvmodelwriter.h
  editaddressdialog.cpp
  editaddressdialog.h
  latticaaddressvalidator.cpp
  latticaaddressvalidator.h
  latticaamountfield.cpp
  latticaamountfield.h
  latticaunits.cpp
  latticaunits.h
  guiconstants.h
  lattica.cpp
  lattica.h
  latticagui.cpp
  latticagui.h
  initexecutor.cpp
  initexecutor.h
  winshutdownmonitor.cpp
  winshutdownmonitor.h
  freespacechecker.cpp
  freespacechecker.h
  intro.cpp
  intro.h
  modaloverlay.cpp
  modaloverlay.h
  notificator.cpp
  notificator.h
  splashscreen.cpp
  splashscreen.h
  trafficgraphwidget.cpp
  trafficgraphwidget.h
  utilitydialog.cpp
  utilitydialog.h
  guiutil.cpp
  guiutil.h
  networkstyle.cpp
  networkstyle.h
  openuridialog.cpp
  openuridialog.h
  optionsdialog.cpp
  optionsdialog.h
  optionsmodel.cpp
  optionsmodel.h
  peertablemodel.cpp
  peertablemodel.h
  peertablesortproxy.cpp
  peertablesortproxy.h
  platformstyle.cpp
  platformstyle.h
  qvalidatedlineedit.cpp
  qvalidatedlineedit.h
  qvaluecombobox.cpp
  qvaluecombobox.h
  qrimagewidget.cpp
  qrimagewidget.h
  rpcconsole.cpp
  rpcconsole.h
  receivecoinsdialog.cpp
  receivecoinsdialog.h
  receiverequestdialog.cpp
  receiverequestdialog.h
  recentrequeststablemodel.cpp
  recentrequeststablemodel.h
  sendcoinsrecipient.h
  coincontroltreewidget.cpp
  coincontroltreewidget.h
  coincontroldialog.cpp
  coincontroldialog.h
  sendcoinsdialog.cpp
  sendcoinsdialog.h
  sendcoinsentry.cpp
  sendcoinsentry.h
  signverifymessagedialog.cpp
  signverifymessagedialog.h
  transactiondescdialog.cpp
  transactiondescdialog.h
  transactionfilterproxy.cpp
  transactionfilterproxy.h
  transactionoverviewwidget.cpp
  transactionoverviewwidget.h
  overviewpage.cpp
  overviewpage.h
  transactionview.cpp
  transactionview.h
  transactiondesc.cpp
  transactiondesc.h
  transactionrecord.cpp
  transactionrecord.h
  transactiontablemodel.cpp
  transactiontablemodel.h
  createwalletdialog.cpp
  createwalletdialog.h
  walletcontroller.cpp
  walletcontroller.h
  walletframe.cpp
  walletframe.h
  walletview.cpp
  walletview.h
  walletmodel.cpp
  walletmodel.h
  walletmodeltransaction.cpp
  walletmodeltransaction.h
)

target_compile_definitions(latticaqt
  PUBLIC
    QT_NO_KEYWORDS
    QT_USE_QSTRINGBUILDER
    # Lattica always builds the wallet into lattica_core, so the GUI's
    # wallet code paths (WalletModel, wallet tab, load-wallet hooks) are
    # unconditionally active.
    ENABLE_WALLET
)

target_include_directories(latticaqt
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)

target_link_libraries(latticaqt
  PUBLIC
    Qt6::Widgets
  PRIVATE
    core_interface
    lattica_node
    lattica_wallet
)

if(WIN32)
  # guiutil.cpp uses PathRemoveFileSpecW from the Windows shell-path API.
  target_link_libraries(latticaqt PRIVATE shlwapi)
endif()

# Compile the .ts translations to .qm via lrelease (depends on latticaqt).
add_subdirectory(locale)

# ---------------------------------------------------------------------------
# The lattica-qt executable. main.cpp holds the entry point (G_TRANSLATION_FUN
# + GuiMain) and init/lattica-qt.cpp provides MakeGuiInit (the GUI's in-process
# node init). qt6_add_executable sets the WIN32/macOS bundle properties and links
# the Qt entry-point library (which calls our dllexport'd main on Windows).
qt6_add_executable(lattica-qt
  main.cpp
  ${CMAKE_SOURCE_DIR}/src/init/lattica-qt.cpp
)
target_link_libraries(lattica-qt
  PRIVATE
    core_interface
    latticaqt
    lattica_node
    lattica_wallet
    # rpcconsole.cpp uses RPCConvertValues from the CLI lib (rpc/client.cpp).
    lattica_cli
)

# Build as a Windows GUI-subsystem app (no console window). Qt's entry-point
# library supplies WinMain, which calls our dllexport'd main (see MAIN_FUNCTION).
set_target_properties(lattica-qt PROPERTIES WIN32_EXECUTABLE TRUE)

if(WIN32)
  # Embed the UTF-8 active-code-page manifest, as the other binaries do.
  # OBJECT_DEPENDS so windres re-embeds the icons when the .ico files change
  # (the .rc ICON statements are not tracked as dependencies otherwise).
  set_source_files_properties(${CMAKE_SOURCE_DIR}/src/lattica-qt.rc
    PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/src
    OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/src/qt/res/icons/lattica.ico;${CMAKE_SOURCE_DIR}/src/qt/res/icons/lattica_testnet.ico;${CMAKE_SOURCE_DIR}/src/qt/res/icons/lattica_regtest.ico")
  target_sources(lattica-qt PRIVATE ${CMAKE_SOURCE_DIR}/src/lattica-qt.rc)
endif()

# ---------------------------------------------------------------------------
# lattica-gui — the multiprocess GUI: same GuiMain, but its MakeGuiInit
# (init/lattica-gui.cpp) connects to a separate lattica-node process over IPC
# instead of running the node in-process. IPC is unix-only (ENABLE_IPC is forced
# off on Windows), so this binary only builds on unix-likes with the GUI enabled.
if(ENABLE_IPC)
  qt6_add_executable(lattica-gui
    main.cpp
    ${CMAKE_SOURCE_DIR}/src/init/lattica-gui.cpp
  )
  target_link_libraries(lattica-gui
    PRIVATE
      core_interface
      latticaqt
      lattica_node
      lattica_wallet
      lattica_cli
      lattica_ipc
  )
endif()
