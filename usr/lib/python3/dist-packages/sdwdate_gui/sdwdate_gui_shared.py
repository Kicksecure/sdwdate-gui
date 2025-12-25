#!/usr/bin/python3 -su

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught

"""
Code shared between sdwdate_gui_client and sdwdate_gui_server.
"""

from typing import Any
import schema  # type: ignore

from strict_config_parser import strict_config_parser


# pylint: disable=too-few-public-methods
class ConfigData:
    """
    Configuration data for sdwdate-gui.
    """

    conf_dir_list: list[str] = [
        "/etc/sdwdate-gui.d",
        "/usr/local/etc/sdwdate-gui.d",
    ]
    conf_schema: schema.Schema = schema.Schema(
        {
            schema.Optional("disable"): bool,
            schema.Optional("run_server_in_qubes"): bool,
            schema.Optional("gateway"): str,
        },
    )
    defaults_dict: dict[str, Any] = {
        "disable": False,
        "run_server_in_qubes": False,
        "gateway": "sys-whonix",
    }
    conf_dict: dict[str, Any] = {}


def check_bytes_printable(buf: bytes) -> bool:
    """
    Checks if all bytes in the provided buffer are printable ASCII.
    """

    for byte in buf:
        if byte < 0x20 or byte > 0x7E:
            return False

    return True


def parse_ipc_command(
    sock_buf: bytes,
) -> tuple[bytes, str | None, list[str] | None]:
    """
    Reads a command from an IPC socket buffer and returns the command name
    and its arguments.
    """

    msg_len: int = int.from_bytes(sock_buf[:2], byteorder="big", signed=False)
    ## Messages should never be even close to 4 KiB in length.
    if msg_len > 4096:
        raise ValueError("Message length too long")
    if len(sock_buf) < (msg_len + 2):
        return sock_buf, None, None
    sock_buf = sock_buf[2:]
    if msg_len == 0:
        return sock_buf, None, None
    msg_buf: bytes = sock_buf[:msg_len]
    sock_buf = sock_buf[msg_len:]
    if not check_bytes_printable(msg_buf):
        raise ValueError("Invalid bytes in command")
    msg_string: str = msg_buf.decode(encoding="ascii")
    msg_parts: list[str] = msg_string.split(" ")
    if len(msg_parts) < 1:
        return sock_buf, None, None
    function_name: str = msg_parts[0]
    msg_parts = msg_parts[1:]
    return sock_buf, function_name, msg_parts


def parse_config_files() -> None:
    """
    Parses config files for sdwdate-gui, modifying the ConfigData class to
    reflect the correct configuration state.
    """

    ConfigData.conf_dict = strict_config_parser.parse_config_files(
        conf_item_list=ConfigData.conf_dir_list,
        conf_schema=ConfigData.conf_schema,
        defaults_dict=ConfigData.defaults_dict,
    )


## Debugging.
if __name__ == "__main__":
    parse_config_files()
    for k, v in ConfigData.conf_dict.items():
        print(f"  {k}: {v}")
