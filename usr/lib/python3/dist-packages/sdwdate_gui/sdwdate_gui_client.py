#!/usr/bin/python3 -su

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,import-error

"""
The client component of sdwdate-gui. Monitors sdwdate and Tor states, reports
these states to the server, and runs commands at the server's request.
"""

import asyncio
import os
import sys
import logging
import subprocess
import json

from collections import deque
from pathlib import Path
from typing import NoReturn, Any

import pyinotify  # type: ignore

from .sdwdate_gui_shared import (
    ConfigData,
    parse_ipc_command,
    parse_config_files,
)


# pylint: disable=too-few-public-methods
class GlobalData:
    """
    Global data for sdwdate_gui_client.
    """

    anon_connection_wizard_installed: bool = False
    sock_read: asyncio.StreamReader | None = None
    sock_write: asyncio.StreamWriter | None = None
    uid_str: str = str(os.getuid())
    sdwdate_run_dir: Path = Path(f"/run/user/{uid_str}/sdwdate-gui")
    server_socket_path: Path = sdwdate_run_dir.joinpath(
        "sdwdate-gui-server.socket",
    )
    server_pid_path: Path = sdwdate_run_dir.joinpath("server_pid")
    do_reconnect: bool = True
    sock_buf: bytes = b""
    sdwdate_status_path: str = "/run/sdwdate/status"
    tor_path: str = "/run/tor"
    torrc_path: str = "/usr/local/etc/torrc.d"
    tor_running_path: str = "/run/tor/tor.pid"
    last_tor_status: str = ""
    watch_manager: pyinotify.WatchManager | None = None
    notifier: pyinotify.AsyncioNotifier | None = None
    awaitable_tasks: deque[asyncio.Task[Any]] = deque()


# pylint: disable=invalid-name
class INotifyEventHandler(pyinotify.ProcessEvent):  # type: ignore[misc]
    """
    Handles incoming inotify events for Tor and sdwdate status files.
    """

    def file_changed(self, path_str: str) -> None:
        """
        Handler for file change events.
        """

        if path_str.startswith(
            f"{GlobalData.tor_path}/"
        ) or path_str.startswith(f"{GlobalData.torrc_path}/"):
            GlobalData.awaitable_tasks.append(
                asyncio.create_task(tor_status_changed())
            )
        elif path_str == GlobalData.sdwdate_status_path:
            GlobalData.awaitable_tasks.append(
                asyncio.create_task(sdwdate_status_changed())
            )
        else:
            logging.error("Unexpected path change at '%s'!", path_str)

    def process_IN_MODIFY(self, event: pyinotify.Event) -> None:
        """
        Modify event handler.
        """
        self.file_changed(event.pathname)

    def process_IN_CREATE(self, event: pyinotify.Event) -> None:
        """
        Create event handler.
        """
        self.file_changed(event.pathname)

    def process_IN_DELETE(self, event: pyinotify.Event) -> None:
        """
        Delete event handler.
        """
        self.file_changed(event.pathname)

    def process_IN_MOVED_FROM(self, event: pyinotify.Event) -> None:
        """
        Moved-from event handler.
        """
        self.file_changed(event.pathname)

    def process_IN_MOVED_TO(self, event: pyinotify.Event) -> None:
        """
        Moved-to event handler.
        """
        self.file_changed(event.pathname)

    def process_IN_DELETE_SELF(self, event: pyinotify.Event) -> None:
        """
        Delete-self event handler.
        """
        if event.pathname == GlobalData.sdwdate_status_path:
            logging.error("sdwdate status path '%s' deleted!", event.pathname)
        else:
            logging.error(
                "BUG: Unexpected file deletion at '%s' detected!",
                event.pathname,
            )

    def process_IN_MOVE_SELF(self, event: pyinotify.Event) -> None:
        """
        Move-self event handler.
        """
        if event.pathname == GlobalData.sdwdate_status_path:
            logging.error("sdwdate status path '%s' moved!", event.pathname)
        else:
            logging.error(
                "BUG: Unexpected file move at '%s' detected!",
                event.pathname,
            )


GlobalData.anon_connection_wizard_installed = os.path.exists(
    "/usr/bin/anon-connection-wizard"
)
if GlobalData.anon_connection_wizard_installed:
    from anon_connection_wizard import tor_status


def running_in_qubes_os() -> bool:
    """
    Detects if the server is running on Qubes OS. The behavior when getting
    the client's name has to be somewhat different on Qubes OS, so we need to
    adjust for that use case.
    """

    if Path("/usr/share/qubes/marker-vm").is_file():
        return True

    return False


async def kick_server() -> None:
    """
    Forcibly disconnects the server from the client. Used as a security
    measure when the server sends invalid data to the client.
    """

    assert GlobalData.sock_write is not None
    logging.error("Invalid data encountered. Disconnecting.")
    GlobalData.sock_write.close()
    await GlobalData.sock_write.wait_closed()


# pylint: disable=too-many-return-statements
async def try_parse_commands() -> None:
    """
    Tries to run any commands in the buffer.
    """

    while len(GlobalData.sock_buf) >= 2:
        function_name: str | None
        msg_parts: list[str] | None
        try:
            preproc_sock_buf_len: int = len(GlobalData.sock_buf)
            GlobalData.sock_buf, function_name, msg_parts = parse_ipc_command(
                GlobalData.sock_buf
            )
            postproc_sock_buf_len: int = len(GlobalData.sock_buf)
            if preproc_sock_buf_len == postproc_sock_buf_len:
                ## If the buffer didn't shrink, that means that we've only
                ## received part of a message. Break so that we can receive
                ## the rest of it later on.
                break
            if function_name is None:
                continue
            assert function_name is not None
            assert msg_parts is not None
        except ValueError:
            await kick_server()
            return

        match function_name:
            case "open_tor_control_panel":
                if len(msg_parts) != 0:
                    await kick_server()
                    return
                open_tor_control_panel()
            case "open_sdwdate_log":
                if len(msg_parts) != 0:
                    await kick_server()
                    return
                open_sdwdate_log()
            case "restart_sdwdate":
                if len(msg_parts) != 0:
                    await kick_server()
                    return
                restart_sdwdate()
            case "stop_sdwdate":
                if len(msg_parts) != 0:
                    await kick_server()
                    return
                stop_sdwdate()
            case "suppress_client_reconnect":
                if len(msg_parts) != 0:
                    await kick_server()
                    return
                suppress_client_reconnect()
            case _:
                await kick_server()
                return


async def handle_incoming_data() -> bool:
    """
    Reads incoming data from the server into a buffer, parsing and running
    commands from the data.
    """

    assert GlobalData.sock_read is not None
    new_data: bytes = await GlobalData.sock_read.read(1024)
    if new_data == b"":
        return False
    GlobalData.sock_buf += new_data
    await try_parse_commands()
    return True


## SERVER-TO-CLIENT RPC CALLS
def open_tor_control_panel() -> None:
    """
    RPC call from server to client. Opens Tor Control Panel.
    """
    # pylint: disable=consider-using-with
    subprocess.Popen(["/usr/bin/tor-control-panel"], shell=False)


def open_sdwdate_log() -> None:
    """
    RPC call from server to client. Opens the sdwdate log in a terminal.
    """
    # pylint: disable=consider-using-with
    subprocess.Popen(["/usr/libexec/sdwdate-gui/log-viewer"], shell=False)


def restart_sdwdate() -> None:
    """
    RPC call from server to client. Restarts the sdwdate service.
    """
    # pylint: disable=consider-using-with
    subprocess.Popen(["leaprun", "sdwdate-clock-jump"], shell=False)


def stop_sdwdate() -> None:
    """
    RPC call from server to client. Stops the sdwdate service.
    """
    # pylint: disable=consider-using-with
    subprocess.Popen(["leaprun", "stop-sdwdate"], shell=False)


def suppress_client_reconnect() -> None:
    """
    RPC call from server to client. Prevents the client from attempting to
    reconnect to the server after a disconnect.
    """
    GlobalData.do_reconnect = False


## CLIENT-TO-SERVER RPC CALLS
async def generic_rpc_call(msg_bytes: bytes) -> None:
    """
    Sends an RCP call from the server to the client, following the wire format
    documented for this module.
    """

    assert GlobalData.sock_write is not None
    msg_len: int = len(msg_bytes)
    msg_buf: bytes = (
        msg_len.to_bytes(2, byteorder="big", signed=False) + msg_bytes
    )
    GlobalData.sock_write.write(msg_buf)
    await GlobalData.sock_write.drain()


async def set_client_name(name: str) -> None:
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

    await generic_rpc_call(b"set_client_name " + name.encode(encoding="ascii"))


async def set_sdwdate_status(status: str, msg: str) -> None:
    """
    RPC call from client to server. Updates the sdwdate status shown by
    the server.
    """

    ## Encode spaces, newlines, and backslashes into octal escapes.
    msg_copy: str = msg.replace("\\", "\\134")
    msg_copy = msg_copy.replace(" ", "\\040")
    msg_copy = msg_copy.replace("\n", "\\012")

    await generic_rpc_call(
        b"set_sdwdate_status "
        + status.encode(encoding="ascii")
        + b" "
        + msg_copy.encode(encoding="ascii")
    )


async def set_tor_status(status: str) -> None:
    """
    RPC call from client to server. Updates the sdwdate status shown by
    the server. This call avoids sending duplicate status change messages.
    """
    if status != GlobalData.last_tor_status:
        GlobalData.last_tor_status = status
        await generic_rpc_call(
            b"set_tor_status " + status.encode(encoding="ascii")
        )


## WATCHER EVENTS
async def sdwdate_status_changed() -> None:
    """
    Determine the current sdwdate status and send it to the server.
    """

    if not os.path.isfile(GlobalData.sdwdate_status_path):
        return

    try:
        with open(GlobalData.sdwdate_status_path, "r", encoding="utf-8") as f:
            status_dict: dict[str, str] = json.load(f)
    except json.decoder.JSONDecodeError as e:
        logging.warning("Could not parse JSON from sdwdate", exc_info=e)
        return
    except Exception as e:
        logging.error("Unexpected error", exc_info=e)
        return

    for check_key in ("icon", "message"):
        if check_key not in status_dict:
            logging.warning(
                "Missing key '%s' in sdwdate status file!",
                check_key,
            )
            return
        if not isinstance(status_dict[check_key], str):
            logging.warning(
                "Key '%s' in sdwdate status file is not a string!",
                check_key,
            )
            return

    status_str: str = status_dict["icon"]
    message_str: str = status_dict["message"]

    if not isinstance(status_str, str) or not isinstance(message_str, str):
        logging.warning("Invalid data found in sdwdate status file!")
        return

    if status_str in ("success", "busy", "error"):
        await set_sdwdate_status(status_str, message_str)
    else:
        logging.warning("Invalid data found in sdwdate status file!")


async def tor_status_changed() -> None:
    """
    Determine the current Tor status and send it to the server.
    """

    if not GlobalData.anon_connection_wizard_installed:
        ## tor_status() unavailable.
        return

    try:
        tor_is_enabled: bool = tor_status.tor_status() == "tor_enabled"
        tor_is_running: bool = os.path.exists(GlobalData.tor_running_path)
    except Exception as e:
        logging.error("Unexpected error", exc_info=e)
        return

    if tor_is_enabled and tor_is_running:
        await set_tor_status("running")
    elif not tor_is_enabled:
        if tor_is_running:
            await set_tor_status("disabled_running")
        else:
            await set_tor_status("disabled")
    else:
        await set_tor_status("stopped")


## SETUP FUNCTIONS
async def open_connection() -> bool:
    """
    Opens a connection with the sdwdate-gui server.
    """

    while not GlobalData.server_socket_path.exists():
        await asyncio.sleep(0.1)
    try:
        GlobalData.sock_read, GlobalData.sock_write = (
            await asyncio.open_unix_connection(GlobalData.server_socket_path)
        )
    except Exception:
        logging.error("Could not connect to sdwdate-gui server!")
        return False
    return True


async def setup_connection() -> None:
    """
    Sends data to the server that will be vital for the rest of the session
    between the client and server.
    """

    assert GlobalData.sock_write is not None
    if GlobalData.server_pid_path.is_file() or not running_in_qubes_os():
        ## We have to send our own blank qrexec header.
        GlobalData.sock_write.write(b"\0")
        await GlobalData.sock_write.drain()

        ## We also have to set our own name.
        if running_in_qubes_os():
            client_name: str = subprocess.run(
                ["qubesdb-read", "/name"],
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
            ).stdout.strip()
            if client_name == "":
                client_name = os.uname()[1]
        else:
            client_name = os.uname()[1]
        await set_client_name(client_name)


async def find_and_handle_tor_and_sdwdate_state() -> tuple[bool, bool]:
    """
    Waits for the Tor and sdwdate state files to appear, sends information
    about them to the server, and determines which files are available to be
    watched via inotify.
    """

    found_tor_paths: bool = False
    found_sdwdate_path: bool = False

    if not GlobalData.anon_connection_wizard_installed:
        await set_tor_status("absent")
    else:
        for _ in range(20):
            if os.path.isdir(GlobalData.tor_path) and os.path.isdir(
                GlobalData.torrc_path
            ):
                found_tor_paths = True
                break
            await asyncio.sleep(1)
        if not found_tor_paths:
            logging.error("tor status or configuration path does not exist!")
            await set_tor_status("disabled")
        else:
            await tor_status_changed()

    for _ in range(20):
        if os.path.isfile(GlobalData.sdwdate_status_path):
            found_sdwdate_path = True
            break
        await asyncio.sleep(1)
    if not found_sdwdate_path:
        logging.error("sdwdate status path does not exist!")
        await set_sdwdate_status("error", "sdwdate status path does not exist!")
        await kick_server()
    await sdwdate_status_changed()

    return found_tor_paths, found_sdwdate_path


async def setup_inotify_watches(
    found_tor_paths: bool,
    found_sdwdate_path: bool,
) -> None:
    """
    Creates the inotify watches.
    """

    GlobalData.watch_manager = pyinotify.WatchManager()
    loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
    GlobalData.notifier = pyinotify.AsyncioNotifier(
        GlobalData.watch_manager, loop, default_proc_fun=INotifyEventHandler()
    )
    if found_tor_paths:
        GlobalData.watch_manager.add_watch(
            GlobalData.tor_path,
            pyinotify.ALL_EVENTS,
            rec=True,
        )
        GlobalData.watch_manager.add_watch(
            GlobalData.torrc_path,
            pyinotify.ALL_EVENTS,
            rec=True,
        )
    if found_sdwdate_path:
        GlobalData.watch_manager.add_watch(
            GlobalData.sdwdate_status_path,
            pyinotify.ALL_EVENTS,
        )


async def do_setup() -> bool:
    """
    Connects to the server and sets up inotify if needed.
    """

    if not await open_connection():
        return False

    try:
        await setup_connection()

        found_tor_paths: bool
        found_sdwdate_path: bool
        found_tor_paths, found_sdwdate_path = (
            await find_and_handle_tor_and_sdwdate_state()
        )
        if not found_sdwdate_path:
            return False

        if GlobalData.watch_manager is None:
            await setup_inotify_watches(found_tor_paths, found_sdwdate_path)

    except Exception:
        logging.error("sdwdate-gui server disconnected very quickly!")
        return False

    return True


async def main_loop() -> None:
    """
    Main loop.
    """

    while True:
        if not await do_setup():
            continue
        while True:
            try:
                in_data_task: asyncio.Task[bool] = asyncio.create_task(
                    handle_incoming_data()
                )
                GlobalData.awaitable_tasks.appendleft(in_data_task)
                start_deque_len: int = len(GlobalData.awaitable_tasks)
                return_vals: list[Any] = await asyncio.gather(
                    *GlobalData.awaitable_tasks,
                    return_exceptions=True,
                )
                for _ in range(start_deque_len):
                    _ = GlobalData.awaitable_tasks.popleft()
                if isinstance(return_vals[0], bool):
                    is_still_connected: bool = return_vals[0]
                    if not is_still_connected:
                        break
                else:
                    break
            except Exception:
                break

        if (
            not running_in_qubes_os()
            or not GlobalData.do_reconnect
            or GlobalData.server_pid_path.is_file()
        ):
            sys.exit(0)
        await asyncio.sleep(1)
        continue


async def main() -> NoReturn:
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

    try:
        parse_config_files()
    except Exception as e:
        logging.error(
            "Configuration file parsing failed!",
            exc_info=e
        )
        sys.exit(1)
    assert isinstance(ConfigData.conf_dict["disable"], bool)
    if ConfigData.conf_dict["disable"]:
        logging.info(
            "'disable' configuration key set to 'True', therefore exiting."
        )
        sys.exit(0)

    await main_loop()
    sys.exit(0)
