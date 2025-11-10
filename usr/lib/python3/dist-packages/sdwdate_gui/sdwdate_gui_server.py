#!/usr/bin/python3 -su

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=no-name-in-module,broad-exception-caught,too-many-lines

"""
The server component of sdwdate-gui. Presents a graphical interface for
sdwdate to the user. Expects to be connected to by one or more
sdwdate_gui_client instances which provide data about sdwdate to the server
component and runs tasks at the server component's request.
"""

import os
import sys
import signal
import re
import functools
import logging

from enum import Enum
from typing import NoReturn, Pattern
from types import FrameType
from pathlib import Path

from PyQt5.QtCore import (
    pyqtSignal,
    Qt,
    QObject,
    QTimer,
)
from PyQt5.QtGui import (
    QIcon,
    QImage,
    QCursor,
    QPixmap,
)
from PyQt5.QtWidgets import (
    QMenu,
    QAction,
    QSystemTrayIcon,
    QApplication,
    QDialog,
    QWidget,
    QLabel,
    QPushButton,
    QGridLayout,
)
from PyQt5.QtNetwork import (
    QLocalSocket,
    QLocalServer,
)

from .sdwdate_gui_shared import (
    ConfigData,
    check_bytes_printable,
    parse_ipc_command,
    parse_config_files,
)


class SdwdateStatus(Enum):
    """
    Status of the sdwdate process running on a client system.
    """

    SUCCESS = 0
    BUSY = 1
    ERROR = 2
    UNKNOWN = 0xFF


class TorStatus(Enum):
    """
    Status of the Tor process running on a client system, if Tor is present on
    the client.
    """

    RUNNING = 0
    STOPPED = 1
    DISABLED = 2
    DISABLED_RUNNING = 3
    ABSENT = 0xFE
    UNKNOWN = 0xFF


class MessageType(Enum):
    """
    Used to specify which status SdwdateTrayIcon.show_status_msg should
    display to the user.
    """

    SDWDATE = 0
    TOR = 1


def running_in_qubes_os() -> bool:
    """
    Detects if the server is running on Qubes OS. The behavior when getting
    the client's name has to be somewhat different on Qubes OS, so we need to
    adjust for that use case.
    """

    if Path("/usr/share/qubes/marker-vm").is_file():
        return True

    return False


# pylint: disable=too-many-instance-attributes
class SdwdateGuiClient(QObject):
    """
    An object representing a sdwdate-gui client. Each client object acts as a
    two-way RPC channel, allowing the server to call certain functions in the
    client and vice versa.

    Each message is sent as a length-prefixed packet. Each length prefix is a
    two-byte, big-endian integer specifying the number of bytes in the
    message. The messages then consist of a string, with space-separated
    words. The first word is the name of the function being called, subsequent
    strings are arguments. Functions do not "return" any values.

    The following functions are provided by the server and can be called by
    the client:
    - set_client_name <name>
    - set_sdwdate_status [success|busy|error] [message]
    - set_tor_status [running|stopped|disabled|disabled_running|absent]

    The following functions are provided by the client and can be called by
    the server:
    - open_tor_control_panel
    - open_sdwdate_log
    - restart_sdwdate
    - stop_sdwdate
    - suppress_client_reconnect
    """

    clientDisconnected: pyqtSignal = pyqtSignal()
    clientNameChanged: pyqtSignal = pyqtSignal()
    sdwdateStatusChanged: pyqtSignal = pyqtSignal()
    torStatusChanged: pyqtSignal = pyqtSignal()

    def __init__(
        self, client_socket: QLocalSocket, parent: QObject | None = None
    ) -> None:
        """
        Creates a new SdwdateGuiClient object from a socket.
        """
        QObject.__init__(self, parent)
        self.client_socket: QLocalSocket = client_socket
        self.client_socket.setParent(self)
        self.client_name: str | None = None
        self.client_name_set: bool = False
        self.sdwdate_status: SdwdateStatus = SdwdateStatus.UNKNOWN
        self.sdwdate_msg: str | None = None
        self.tor_status: TorStatus = TorStatus.UNKNOWN
        self.qubes_header_parsed: bool = False

        self.__sock_buf: bytes = b""

        self.client_socket.readyRead.connect(self.__handle_incoming_data)
        self.client_socket.disconnected.connect(self.clientDisconnected.emit)

    def client_name_or_unknown(self) -> str:
        """
        Returns the client name if set, otherwise returns "Unknown".
        """

        if self.client_name is not None:
            return self.client_name

        return "Unknown"

    def kick_client(self) -> None:
        """
        Forcibly disconnects the client from the server. Used when a client
        sends invalid data to the server as a security measure.
        """

        if running_in_qubes_os():
            ## Under Qubes OS, the client will automatically reconnect if the
            ## server disconnects it. Suggest to the client that it not do
            ## that. Assuming the cause of client misbehavior is simply a bug,
            ## this should help prevent endless reconnect loops. Note that the
            ## client may disregard this; we cannot assume the client won't
            ## try to reconnect after receiving this.
            self.suppress_client_reconnect()

        self.client_socket.disconnectFromServer()
        self.clientDisconnected.emit()

    ## SOCKET MANAGEMENT
    def __parse_qubes_data(self) -> bool:
        """
        Gets the client name from the qrexec connection header if possible.
        """

        qrexec_header_bytes: bytes | None = None
        for idx, byte in enumerate(self.__sock_buf):
            if byte == 0:
                qrexec_header_bytes = self.__sock_buf[:idx]
                self.__sock_buf = self.__sock_buf[idx + 1 :]
                break

        if qrexec_header_bytes is None:
            if len(self.__sock_buf) > 4096:
                logging.warning(
                    "Kicking client '%s' for sending too much data in qrexec "
                    "header",
                    self.client_name_or_unknown(),
                )
                self.kick_client()
            return False

        if not check_bytes_printable(qrexec_header_bytes):
            logging.warning(
                "Kicking client '%s' for sending invalid bytes in qrexec "
                "header",
                self.client_name_or_unknown(),
            )
            self.kick_client()
            return False

        self.qubes_header_parsed = True

        qrexec_header: str = qrexec_header_bytes.decode("ascii")
        qrexec_header_parts = qrexec_header.split(" ")
        if len(qrexec_header_parts) < 2:
            return True

        self.client_name = qrexec_header_parts[1]
        self.client_name_set = True

        return True

    # pylint: disable=too-many-return-statements
    def __try_parse_commands(self) -> None:
        """
        Tries to run any commands in the buffer.
        """

        while len(self.__sock_buf) >= 2:
            function_name: str | None
            msg_parts: list[str] | None
            try:
                self.__sock_buf, function_name, msg_parts = parse_ipc_command(
                    self.__sock_buf
                )
                if function_name is None:
                    continue
                assert function_name is not None
                assert msg_parts is not None
            except ValueError:
                logging.warning(
                    "Kicking client '%s' for sending invalid bytes in "
                    "command buffer",
                    self.client_name_or_unknown(),
                )
                self.kick_client()
                return

            match function_name:
                case "set_client_name":
                    if len(msg_parts) != 1:
                        logging.warning(
                            "Kicking client '%s' for sending incorrect "
                            "number of arguments for 'set_client_name' "
                            "call",
                            self.client_name_or_unknown(),
                        )
                        self.kick_client()
                        return
                    if not self.__set_client_name(msg_parts[0]):
                        return
                case "set_sdwdate_status":
                    if len(msg_parts) != 2:
                        logging.warning(
                            "Kicking client '%s' for sending incorrect "
                            "number of arguments for 'set_sdwdate_status' "
                            "call",
                            self.client_name_or_unknown(),
                        )
                        self.kick_client()
                        return
                    if not self.__set_sdwdate_status(
                        msg_parts[0], msg_parts[1]
                    ):
                        return
                case "set_tor_status":
                    if len(msg_parts) != 1:
                        logging.warning(
                            "Kicking client '%s' for sending incorrect "
                            "number of arguments for 'set_tor_status' "
                            "call",
                            self.client_name_or_unknown(),
                        )
                        self.kick_client()
                        return
                    if not self.__set_tor_status(msg_parts[0]):
                        return

    def __handle_incoming_data(self) -> None:
        """
        Reads incoming data from the client into a buffer, parsing and running
        commands from the data.
        """

        self.__sock_buf += self.client_socket.readAll().data()

        if not self.qubes_header_parsed:
            if not self.__parse_qubes_data():
                return

        self.__try_parse_commands()

    ## CLIENT-TO-SERVER RPC CALLS
    def __set_client_name(self, client_name: str) -> bool:
        """
        RPC call from client to server. Sets the client's name on the
        server side.

        IMPORTANT: On non-Qubes systems, this data MUST be provided by the
        client itself, while on Qubes OS, this data MUST be provided by the
        qrexec subsystem. NOT provided by the client. If a client never
        sends a client name, the client will never appear in the GUI on
        non-Qubes systems, while if the client always sends a client name,
        the server will forcibly disconnect it under Qubes OS.
        """

        if self.client_name_set:
            ## Client is attempting to change its name after already providing
            ## it once, kick it
            logging.warning(
                "Kicking client '%s' for attempting to change its name to "
                "'%s'",
                self.client_name_or_unknown(),
                client_name,
            )
            self.kick_client()
            return False

        if running_in_qubes_os():
            ## Name rules taken from Qubes OS
            ## (qubes-core-admin/qubes/vm/__init__.py)
            if (
                ## Name must be shorter than 32 characters
                len(client_name) > 31
                ## Name must consist of alphanumeric characters, numbers, underscores,
                ## dots, and hyphens, and the first character must be an alphabetic
                ## character
                or re.match(r"\A[a-zA-Z][a-zA-Z0-9_.-]*\Z", client_name) is None
                ## Name cannot be "Domain-0", "none", or "default"
                or client_name in ("Domain-0", "none", "default")
                ## Name cannot end in "-dm"
                or client_name.endswith("-dm")
            ):
                logging.warning(
                    "Kicking client '%s' for attempting to set invalid name '%s'",
                    self.client_name_or_unknown(),
                    client_name,
                )
                self.kick_client()
                return False
        else:
            ## Less restrictive set of rules for outside of Qubes OS
            ## Name must be shorter than 256 characters
            if len(client_name) > 255:
                logging.warning(
                    "Kicking client '%s' for attempting to set invalid name '%s'",
                    self.client_name_or_unknown(),
                    client_name,
                )
                self.kick_client()
                return False

        self.client_name = client_name
        self.client_name_set = True
        self.clientNameChanged.emit()
        return True

    def __set_sdwdate_status(
        self, sdwdate_status_str: str, sdwdate_msg_str: str
    ) -> bool:
        """
        RPC call from client to server. Updates the sdwdate status shown by
        the server.
        """

        if not self.client_name_set:
            logging.warning(
                "Kicking client '%s' for attempting to set sdwdate status "
                "before setting name",
                self.client_name_or_unknown(),
            )
            self.kick_client()
            return False

        match sdwdate_status_str:
            case "success":
                self.sdwdate_status = SdwdateStatus.SUCCESS
            case "busy":
                self.sdwdate_status = SdwdateStatus.BUSY
            case "error":
                self.sdwdate_status = SdwdateStatus.ERROR
            case _:
                logging.warning(
                    "Kicking client '%s' for attempting to set an invalid "
                    "status of '%s'",
                    self.client_name_or_unknown(),
                    sdwdate_status_str,
                )
                self.kick_client()
                return False

        decode_re: Pattern[str] = re.compile(r"\\\d{3}")
        octal_escape_set: set[str] = set(decode_re.findall(sdwdate_msg_str))
        for octal_escape in octal_escape_set:
            octal_str: str = octal_escape.strip("\\")
            try:
                octal_int: int = int(octal_str, 8)
            except ValueError:
                logging.warning(
                    "Kicking client '%s' for sending an invalid octal escape "
                    "code '%s' in sdwdate status message '%s' ",
                    self.client_name_or_unknown(),
                    octal_str,
                    sdwdate_msg_str,
                )
                self.kick_client()
                return False

            if octal_int < 0x20 or octal_int > 0x7E and octal_int != 0x0A:
                logging.warning(
                    "Kicking client '%s' for attempting to embed unsafe "
                    "character as octal escape '%s' in sdwdate status "
                    "message '%s'",
                    self.client_name_or_unknown(),
                    octal_str,
                    sdwdate_msg_str,
                )
                self.kick_client()
                return False

            real_char: str = chr(octal_int)
            sdwdate_msg_str = sdwdate_msg_str.replace(octal_escape, real_char)
        self.sdwdate_msg = sdwdate_msg_str

        self.sdwdateStatusChanged.emit()
        return True

    def __set_tor_status(self, tor_status_str: str) -> bool:
        """
        RPC call from client to server. Updates the sdwdate status shown by
        the server.
        """

        if not self.client_name_set:
            logging.warning(
                "Kicking client '%s' for attempting to set tor status "
                "before setting name",
                self.client_name_or_unknown(),
            )
            self.kick_client()
            return False

        match tor_status_str:
            case "running":
                self.tor_status = TorStatus.RUNNING
            case "stopped":
                self.tor_status = TorStatus.STOPPED
            case "disabled":
                self.tor_status = TorStatus.DISABLED
            case "disabled_running":
                self.tor_status = TorStatus.DISABLED_RUNNING
            case "absent":
                self.tor_status = TorStatus.ABSENT
            case _:
                logging.warning(
                    "Kicking client '%s' for attempting to set an invalid "
                    "Tor status of '%s'",
                    self.client_name_or_unknown(),
                    tor_status_str,
                )
                self.kick_client()
                return False

        self.torStatusChanged.emit()
        return True

    ## SERVER-TO-CLIENT RPC CALLS
    def __generic_rpc_call(self, msg_bytes: bytes) -> None:
        """
        Sends an RPC call from the server to the client, following the wire
        format documented for this object.
        """

        msg_len: int = len(msg_bytes)
        msg_buf: bytes = (
            msg_len.to_bytes(2, byteorder="big", signed=False) + msg_bytes
        )
        msg_len += 2
        while msg_len > 0:
            if self.client_socket.state() != QLocalSocket.ConnectedState:
                return
            bytes_written: int = self.client_socket.write(
                msg_buf[len(msg_buf) - msg_len :]
            )
            msg_len -= bytes_written

    def open_tor_control_panel(self) -> None:
        """
        RPC call from server to client. Opens Tor control panel on the
        client machine.
        """

        if self.tor_status in (TorStatus.ABSENT, TorStatus.UNKNOWN):
            return

        self.__generic_rpc_call(b"open_tor_control_panel")

    def open_sdwdate_log(self) -> None:
        """
        RPC call from server to client. Opens a terminal displaying the
        sdwdate logs on the client machine.
        """

        self.__generic_rpc_call(b"open_sdwdate_log")

    def restart_sdwdate(self) -> None:
        """
        RPC call from server to client. Restarts sdwdate on the client
        machine.
        """

        self.__generic_rpc_call(b"restart_sdwdate")

    def stop_sdwdate(self) -> None:
        """
        RPC call from server to client. Stops sdwdate on the client machine.
        """

        self.__generic_rpc_call(b"stop_sdwdate")

    def suppress_client_reconnect(self) -> None:
        """
        RPC call from server to client. Suggests to the client that it not
        restart itself after being disconnected from the server. This is
        strictly advisory, the server must NOT depend on the client obeying
        this suggestion.
        """

        self.__generic_rpc_call(b"suppress_client_reconnect")


# pylint: disable=too-few-public-methods
class SdwdateGuiFrame(QDialog):
    """
    A window displaying sdwdate or tor status based on information provided by
    a client.
    """

    def __init__(
        self,
        text: str,
        icon_path: str,
        parent: QWidget | None = None,
    ) -> None:
        """
        Constructs the window object. You can immediately move the window
        to the desired location and then show it, no further initialization is
        needed.
        """

        QDialog.__init__(self, parent)
        self.setWindowTitle("Time Synchronization Monitor")
        self.setMinimumWidth(200)

        icon_widget = QLabel(self)
        image = QImage(icon_path)
        icon_widget.setAlignment(Qt.AlignRight)
        icon_widget.setPixmap(QPixmap.fromImage(image))

        text_widget = QLabel(self)
        text_widget.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByMouse
        )
        text_widget.setTextFormat(Qt.RichText)
        text_widget.setAlignment(Qt.AlignTop)
        text_widget.setText(text)

        close_button = QPushButton("Close", self)
        close_button.setMaximumWidth(50)
        close_button.clicked.connect(self.quiet_close)

        frame_content = QGridLayout(self)
        frame_content.addWidget(icon_widget, 0, 0, 1, 1)
        frame_content.addWidget(text_widget, 0, 1, 1, 2)
        frame_content.addWidget(close_button, 1, 1, 1, 2)

    def quiet_close(self) -> None:
        """
        Close the window and return nothing.
        """

        self.close()


class SdwdateTrayIcon(QSystemTrayIcon):
    """
    The core GUI of sdwdate-gui. Displays a system tray icon with a context
    menu, providing info about sdwdate and Tor status and allowing
    configuring certain aspects of both services on the client side.
    """

    def __init__(self, parent: QObject | None = None):
        """
        Initializes the tray icon.
        """

        QSystemTrayIcon.__init__(self, parent)

        self.title: str = "Time Synchronization Monitor"

        self.client_list: list[SdwdateGuiClient] = []

        self.clicked_once: bool = False
        self.pos_x: int = 0
        self.pos_y: int = 0
        self.msg_window: SdwdateGuiFrame | None = None
        self.msg_window_client: str | None = None
        self.msg_window_type: MessageType | None = None

        self.icon_path: str = "/usr/share/sdwdate-gui/icons/"
        self.tor_icon_list: list[str] = [
            self.icon_path + "tor-ok.png",
            self.icon_path + "tor-error.png",
            self.icon_path + "tor-error.png",
            self.icon_path + "tor-warning.png",
        ]
        self.sdwdate_icon_list: list[str] = [
            self.icon_path + "sdwdate-success.png",
            self.icon_path + "sdwdate-wait.png",
            self.icon_path + "sdwdate-stopped.png",
        ]
        self.setIcon(QIcon(self.sdwdate_icon_list[SdwdateStatus.BUSY.value]))
        self.setToolTip("Time Synchronization Monitor \nRight-click for menu.")

        self.menu: QMenu = QMenu()
        self.regen_menu()
        self.setContextMenu(self.menu)
        self.activated.connect(self.show_menu)

        self.listener: SdwdateGuiListener = SdwdateGuiListener(self)
        self.listener.newClient.connect(self.accept_client)

    def show_status_msg(
        self,
        message_type: MessageType,
        client: SdwdateGuiClient,
    ) -> None:
        """
        Shows a status window for the specified client, showing either the
        sdwdate or the Tor state depending on the value of `message_type`.
        """

        if not self.clicked_once:
            self.pos_x = QCursor.pos().x() - 50
            self.pos_y = QCursor.pos().y() - 50
            self.clicked_once = True

        msg_window: SdwdateGuiFrame | None

        if message_type == MessageType.SDWDATE:
            if client.sdwdate_msg is None:
                return
            if running_in_qubes_os():
                msg_window = SdwdateGuiFrame(
                    "Last message from sdwdate on "
                    f"{client.client_name}:<br><br>" + client.sdwdate_msg,
                    self.sdwdate_icon_list[client.sdwdate_status.value],
                )
            else:
                msg_window = SdwdateGuiFrame(
                    "Last message from sdwdate:<br><br>" + client.sdwdate_msg,
                    self.sdwdate_icon_list[client.sdwdate_status.value],
                )
        else:  # message_type == MessageType.TOR
            msg_text: str
            match client.tor_status:
                case TorStatus.RUNNING:
                    msg_text = "Tor is running."
                case TorStatus.DISABLED:
                    msg_text = """\
<b>Tor is disabled</b>. Therefore you most likely<br> \
can not connect to the internet. <br><br> \
Run <b>Anon Connection Wizard</b> from the menu."""
                case TorStatus.STOPPED:
                    msg_text = """\
<b>Tor is not running.</b> <br><br> \
You have to fix this error, before you can use Tor. <br> \
Please restart Tor after fixing this error. <br><br> \
Start Menu -> System -> Restart Tor GUI<br> \
or in Terminal: <br> \
sudo service tor@default restart <br><br>"""
                case TorStatus.DISABLED_RUNNING:
                    msg_text = """\
<b>Tor is running but is disabled.</b><br><br> \
A line <i>DisableNetwork 1</i> exists in torrc <br> \
Run <b>Anon Connection Wizard</b> from the menu <br>\
to connect to or configure the Tor network."""
                case _:
                    logging.warning(
                        "'show_status_msg' called with 'message_type' == "
                        "'MessageType.TOR', but Tor status is 'ABSENT' or "
                        "'UNKNOWN'!"
                    )
                    return

            if running_in_qubes_os():
                msg_window = SdwdateGuiFrame(
                    f"Tor status on {client.client_name}:<br><br>" + msg_text,
                    self.tor_icon_list[client.tor_status.value],
                )
            else:
                msg_window = SdwdateGuiFrame(
                    "Tor status:<br><br>" + msg_text,
                    self.tor_icon_list[client.tor_status.value],
                )

        if self.msg_window is not None and self.msg_window.isVisible():
            self.msg_window.close()
            self.msg_window.deleteLater()

        self.msg_window = msg_window
        self.msg_window_type = message_type
        self.msg_window_client = client.client_name
        self.msg_window.move(self.pos_x, self.pos_y)
        self.msg_window.show()

    # pylint: disable=too-many-statements
    def regen_menu(self) -> None:
        """
        Regenerates the context menu for the tray icon.
        """

        self.menu.clear()

        for client in self.client_list:
            if client.client_name is None:
                continue

            ## Client icon is the client's sdwdate status icon, unless the
            ## client is Tor-enabled and Tor is stopped or disabled.
            ##
            ## client.tor_status will be TorStatus.ABSENT if the client is not
            ## Tor-enabled, so we don't have to explicitly check if the client
            ## is Tor-enabled or not.
            client_icon: QIcon
            if client.tor_status in (TorStatus.STOPPED, TorStatus.DISABLED):
                client_icon = QIcon(
                    self.tor_icon_list[client.tor_status.value],
                )
            elif client.sdwdate_status != SdwdateStatus.UNKNOWN:
                client_icon = QIcon(
                    self.sdwdate_icon_list[client.sdwdate_status.value],
                )
            else:
                continue

            ## Each client gets its own submenu, unless there's only one
            ## client.
            if len(self.client_list) > 1:
                action_menu: QMenu | None = self.menu.addMenu(
                    client_icon,
                    client.client_name,
                )
            else:
                action_menu = self.menu
            assert action_menu is not None

            ## Tor-enabled clients get two extra menu items, one for Tor
            ## status,and one to open the Tor control panel.
            if client.tor_status != TorStatus.ABSENT:
                ## ACTION: Tor status
                target_tor_status: TorStatus
                if client.tor_status in (TorStatus.ABSENT, TorStatus.UNKNOWN):
                    target_tor_status = TorStatus.STOPPED
                else:
                    target_tor_status = client.tor_status
                action: QAction = QAction(
                    QIcon(self.tor_icon_list[target_tor_status.value]),
                    "Show Tor status",
                    action_menu,
                )
                action.triggered.connect(
                    functools.partial(
                        self.show_status_msg, MessageType.TOR, client
                    )
                )
                action_menu.addAction(action)

                ## ACTION: Tor control panel
                action = QAction(
                    QIcon(self.icon_path + "advancedsettings.ico"),
                    "Tor control panel",
                    action_menu,
                )
                action.triggered.connect(
                    functools.partial(client.open_tor_control_panel)
                )
                action_menu.addAction(action)
                action_menu.addSeparator()

            ## ACTION: Sdwdate status
            target_sdwdate_status: SdwdateStatus
            if client.sdwdate_status == SdwdateStatus.UNKNOWN:
                target_sdwdate_status = SdwdateStatus.BUSY
            else:
                target_sdwdate_status = client.sdwdate_status
            action = QAction(
                QIcon(self.sdwdate_icon_list[target_sdwdate_status.value]),
                "Show sdwdate status",
                action_menu,
            )
            action.triggered.connect(
                functools.partial(
                    self.show_status_msg,
                    MessageType.SDWDATE,
                    client,
                )
            )
            action_menu.addAction(action)
            action_menu.addSeparator()

            ## ACTION: Show sdwdate log
            action = QAction(
                QIcon(self.icon_path + "sdwdate-log.png"),
                "Open sdwdate's log",
                action_menu,
            )
            action.triggered.connect(functools.partial(client.open_sdwdate_log))
            action_menu.addAction(action)

            ## ACTION: Sdwdate restart
            action = QAction(
                QIcon(self.icon_path + "restart-sdwdate.png"),
                "Restart sdwdate",
                action_menu,
            )
            action.triggered.connect(functools.partial(client.restart_sdwdate))
            action_menu.addAction(action)

            ## ACTION: Sdwdate stop
            action = QAction(
                QIcon(self.icon_path + "stop-sdwdate.png"),
                "Stop sdwdate",
                action_menu,
            )
            action.triggered.connect(functools.partial(client.stop_sdwdate))
            action_menu.addAction(action)

        self.menu.addSeparator()

        ## Add a button to quit the sdwdate GUI server underneath all the
        ## client entries
        action = QAction(
            QIcon(self.icon_path + "application-exit.png"),
            "&Exit",
            self.menu,
        )
        action.triggered.connect(sys.exit)
        self.menu.addAction(action)

    def set_tray_icon(self) -> None:
        """
        Sets the system tray icon for the applet based on the status of
        connected clients.
        """

        sdwdate_status_index: int = -1
        tor_status_index: int = -1

        for client in self.client_list:
            if (
                client.sdwdate_status != SdwdateStatus.UNKNOWN
                and client.sdwdate_status.value > sdwdate_status_index
            ):
                sdwdate_status_index = client.sdwdate_status.value

            if (
                client.tor_status != TorStatus.ABSENT
                and client.tor_status != TorStatus.UNKNOWN
                and client.tor_status.value > tor_status_index
            ):
                tor_status_index = client.tor_status.value

        if tor_status_index in (
            TorStatus.STOPPED.value,
            TorStatus.DISABLED.value,
        ):
            self.setIcon(QIcon(self.tor_icon_list[tor_status_index]))
        elif sdwdate_status_index > -1:
            self.setIcon(QIcon(self.sdwdate_icon_list[sdwdate_status_index]))

        ## Continue without setting a new icon if both of these checks flunk.

    def show_menu(self, event: QSystemTrayIcon.ActivationReason) -> None:
        """
        Swallows left-clicks on the context menu. This method of showing the
        context menu is broken under Wayland, right-clicking should be used
        instead.

        TODO: Figure out how to get left-clicking to work rather than just
        disabling it.
        """

        # if event == QSystemTrayIcon.ActivationReason.Trigger:
        #    self.menu.exec_(QCursor.pos())

    def handle_client_name_change(
        self,
        sender_client: SdwdateGuiClient,
    ) -> None:
        """
        Updates the client's name. This can only be done once, if a client
        tries to update its name to the name of an existing client it will be
        kicked.
        """

        name_match_count: int = 0
        for client in self.client_list:
            if client.client_name == sender_client.client_name:
                name_match_count += 1
                if name_match_count > 1:
                    logging.warning(
                        "Kicking client '%s' for attempting to set a name "
                        "'%s' identical to another client's name",
                        client.client_name_or_unknown(),
                        client.client_name,
                    )
                    sender_client.kick_client()
                    return

        self.regen_menu()

    def handle_state_change(
        self,
        message_type: MessageType,
        message_client: SdwdateGuiClient,
    ) -> None:
        """
        Handles sdwdate and Tor state changes in any running client.
        """

        if self.msg_window is not None and self.msg_window.isVisible():
            if (
                message_type == self.msg_window_type
                and message_client.client_name == self.msg_window_client
            ):
                self.show_status_msg(message_type, message_client)

        self.regen_menu()
        self.set_tray_icon()

    def drop_client(self, sender_client: SdwdateGuiClient) -> None:
        """
        Purges a disconnected client from the client list.
        """

        sender_client.deleteLater()

        for idx, client in enumerate(self.client_list):
            if client == sender_client:
                self.client_list.pop(idx)
                self.regen_menu()
                self.set_tray_icon()
                return

        logging.warning("Dropped client not present in client list!")

    def accept_client(self, client: SdwdateGuiClient) -> None:
        """
        Adds a new client to the client list.
        """

        self.client_list.append(client)
        client.clientNameChanged.connect(
            functools.partial(
                self.handle_client_name_change,
                client,
            )
        )
        client.sdwdateStatusChanged.connect(
            functools.partial(
                self.handle_state_change,
                message_type=MessageType.SDWDATE,
                message_client=client,
            )
        )
        client.torStatusChanged.connect(
            functools.partial(
                self.handle_state_change,
                message_type=MessageType.TOR,
                message_client=client,
            )
        )
        client.clientDisconnected.connect(
            functools.partial(
                self.drop_client,
                client,
            )
        )


class SdwdateGuiListener(QObject):
    """
    Listens for new client connections and creates SdwdateGuiClient objects
    for them.
    """

    newClient: pyqtSignal = pyqtSignal(SdwdateGuiClient)

    def __init__(self, parent: QObject | None = None) -> None:
        """
        Initializes a listening socket.
        """

        QObject.__init__(self, parent)

        uid_str: str = str(os.getuid())
        sdwdate_run_dir: Path = Path(f"/run/user/{uid_str}/sdwdate-gui")
        sdwdate_pid_file = sdwdate_run_dir.joinpath("server_pid")
        sdwdate_socket_file = sdwdate_run_dir.joinpath(
            "sdwdate-gui-server.socket"
        )
        try:
            sdwdate_run_dir.mkdir(
                parents=True,
                exist_ok=True,
            )
        except Exception:
            logging.error(
                "Could not create '%s' directory!'!",
                str(sdwdate_run_dir),
            )
            sys.exit(1)

        ## This PID file mechanism is prone to race conditions. If we were
        ## trying to be highly robust, we'd want to use advisory locking via
        ## os.lockf rather than a PID file. That would probably be overkill
        ## for this applet though, as the OS will only ever try to start once
        ## instance of the server per logged-in user account, unless the
        ## end-user is intentionally trying to run multiple server instances.
        if sdwdate_pid_file.is_file():
            try:
                with open(sdwdate_pid_file, "r", encoding="utf-8") as f:
                    sdwdate_pid_str: str = f.readline().strip()
                pid_verify_re: Pattern[str] = re.compile("^[0-9]+$")
                if not pid_verify_re.match(sdwdate_pid_str):
                    logging.error(
                        "PID marker file contains non-numeric characters!",
                    )
                    sys.exit(1)
                if Path(f"/proc/{sdwdate_pid_str}").is_dir():
                    logging.error(
                        "sdwdate_gui_server is already running!",
                    )
                    sys.exit(1)
            except Exception as e:
                logging.error(
                    "Could not check for running sdwdate_gui_server!",
                    exc_info=e,
                )
                sys.exit(1)

        try:
            os.remove(sdwdate_pid_file)
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(
                "Could not erase old PID file!",
                exc_info=e,
            )
            sys.exit(1)

        try:
            with open(sdwdate_pid_file, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
        except Exception as e:
            logging.error(
                "Could not save PID to PID file!",
                exc_info=e,
            )
            sys.exit(1)

        try:
            os.remove(sdwdate_socket_file)
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(
                "Could not erase old server socket!",
                exc_info=e,
            )
            sys.exit(1)

        self.server: QLocalServer = QLocalServer(self)
        self.server.listen(str(sdwdate_socket_file))
        self.server.newConnection.connect(self.spawn_client)

    def spawn_client(self) -> None:
        """
        Creates a new client and provides the new client to a listening
        object via a signal.
        """

        new_socket: QLocalSocket | None = self.server.nextPendingConnection()
        assert new_socket is not None
        client: SdwdateGuiClient = SdwdateGuiClient(new_socket, self)
        self.newClient.emit(client)


# pylint: disable=unused-argument
def signal_handler(sig: int, frame: FrameType | None) -> None:
    """
    Handles SIGINT and SIGTERM.
    """

    logging.info("Received SIGINT or SIGTERM, exiting.")
    sys.exit(128 + sig)


def main() -> NoReturn:
    """
    Main function.
    """

    if os.geteuid() == 0:
        print("ERROR: Do not run with sudo / as root!")
        sys.exit(1)

    if Path("/run/qubes/this-is-templatevm").is_file():
        print("INFO: Refusing to run in a QubesOS TemplateVM.")
        sys.exit(0)

    logging.basicConfig(
        format="%(funcName)s: %(levelname)s: %(message)s", level=logging.INFO
    )

    app: QApplication = QApplication(["Sdwdate"])
    app.setQuitOnLastWindowClosed(False)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        parse_config_files()
    except Exception as e:
        logging.error(
            "Configuration file parsing failed!",
            exc_info=e
        )
        sys.exit(1)
    assert isinstance(ConfigData.conf_dict["disable"], bool)
    assert isinstance(ConfigData.conf_dict["run_server_in_qubes"], bool)
    if ConfigData.conf_dict["disable"]:
        logging.info(
            "'disable' configuration key set to 'True', therefore exiting."
        )
        sys.exit(0)
    if running_in_qubes_os():
        if not ConfigData.conf_dict["run_server_in_qubes"]:
            logging.info(
                "Running in Qubes OS, but 'run_server_in_qubes' config is "
                "set to 'False', therefore exiting."
            )
            sys.exit(0)

    timer: QTimer = QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    sdwdate_tray: SdwdateTrayIcon = SdwdateTrayIcon()
    sdwdate_tray.show()
    app.exec_()
    sys.exit(0)
