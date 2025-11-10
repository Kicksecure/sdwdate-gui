#!/usr/bin/python3 -su

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught

"""
Code shared between sdwdate_gui_client and sdwdate_gui_server.
"""

from pathlib import Path
from typing import Any

import tomllib


# pylint: disable=too-few-public-methods
class ConfigData:
    """
    Configuration data for sdwdate-gui.
    """

    conf_dir_list: list[str] = [
        "/etc/sdwdate-gui.d",
        "/usr/local/etc/sdwdate-gui.d",
    ]
    conf_schema: dict[str, str] = {
        "disable": "bool",
        "run_server_in_qubes": "bool",
        "gateway": "str",
    }
    conf_dict: dict[str, Any] = {
        "disable": False,
        "run_server_in_qubes": False,
        "gateway": "sys-whonix",
    }


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

    config_file_list: list[Path] = []

    for dir_item in ConfigData.conf_dir_list:
        config_file_sub_list: list[Path] = []
        dir_path = Path(dir_item)
        if not dir_path.is_dir():
            continue
        for config_file in dir_path.iterdir():
            if not config_file.is_file():
                continue
            if not config_file.name.endswith(".conf"):
                continue
            config_file_sub_list.append(config_file)
        config_file_sub_list.sort()
        config_file_list.extend(config_file_sub_list)

    for config_file in config_file_list:
        with open(config_file, "rb") as f:
            conf_dict: dict[str, Any] = tomllib.load(f)
            for schema_key, schema_val in ConfigData.conf_schema.items():
                if schema_key not in conf_dict:
                    continue
                match schema_val:
                    case "bool":
                        if not isinstance(conf_dict[schema_key], bool):
                            raise ValueError(f"{schema_key}_not_bool")
                    case "str":
                        if not isinstance(conf_dict[schema_key], str):
                            raise ValueError(f"{schema_key}_not_str")
                ConfigData.conf_dict[schema_key] = conf_dict[schema_key]

## Debugging.
if __name__ == "__main__":
    parse_config_files()
    for k, v in ConfigData.conf_dict.items():
        print(f"  {k}: {v}")
