#!/usr/bin/env python3

from .otp_manager import OTPManager
from .cli import parse_arguments, handle_cli_commands


def main():
    args = parse_arguments()
    manager = OTPManager()
    handle_cli_commands(args, manager)


if __name__ == "__main__":
    main()
