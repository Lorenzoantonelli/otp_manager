import argparse
from getpass import getpass
import sys
import shutil
import subprocess
from .clipboard_utils import text_to_clipboard


def parse_arguments():
    parser = argparse.ArgumentParser(description="OTP Manager")

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "-u", "--unlock", action="store_true", help="Unlock the OTP manager"
    )
    action_group.add_argument(
        "-l", "--lock", action="store_true", help="Lock the OTP manager"
    )
    action_group.add_argument("-a", "--add", metavar="SERVICE", help="Add a new secret")
    action_group.add_argument(
        "-d", "--delete", metavar="SERVICE", help="Delete a secret"
    )
    action_group.add_argument(
        "-g",
        "--generate",
        nargs="?",
        const="",
        metavar="SERVICE",
        help="Generate OTP for a service. If no service is provided, enter interactive mode.",
    )
    action_group.add_argument(
        "-ls", "--list", action="store_true", help="List all services"
    )
    action_group.add_argument(
        "-i",
        "--import",
        metavar="FILE",
        dest="import_file",
        help="Import secrets from Aegis JSON file",
    )
    action_group.add_argument(
        "-r",
        "--rename",
        nargs=2,
        metavar=("OLD_NAME", "NEW_NAME"),
        help="Rename a service",
    )

    parser.add_argument("-s", "--secret", help="Secret value for adding or updating")
    parser.add_argument(
        "--digits", type=int, default=6, help="Number of digits for OTP (default: 6)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Time interval for OTP in seconds (default: 30)",
    )
    parser.add_argument(
        "-c", "--copy", action="store_true", help="Copy generated OTP to clipboard"
    )

    return parser.parse_args()


def is_gum_available():
    return shutil.which("gum") is not None


def select_service_interactively(manager):
    if not is_gum_available():
        print(
            "Error: 'gum' is not installed. Please install it to use the interactive mode."
        )
        print("You can install gum from https://github.com/charmbracelet/gum")
        return None

    try:
        services = manager.list_secrets(return_list=True)
        if not services:
            print("No services found.")
            return None

        gum_input = "\n".join(services)

        process = subprocess.Popen(
            ["gum", "filter"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

        stdout, _ = process.communicate(input=gum_input)

        if process.returncode == 0:
            return stdout.strip()
        else:
            print("No service selected.")
            return None
    except FileNotFoundError:
        print(
            "Error: 'gum' is not installed. Please install it to use the interactive mode."
        )
        return None


def handle_cli_commands(args, manager):
    if args.lock:
        manager.lock()
        return

    if not manager.load_session():
        if not args.unlock:
            print("Session expired or not found. Please unlock the OTP manager.")
            sys.exit(1)
        password = getpass("Enter your master password: ")
        if not manager.unlock(password):
            print("Failed to unlock OTP manager.")
            sys.exit(1)
    elif args.unlock:
        print("OTP manager is already unlocked.")
        return

    if args.add:
        secret = args.secret if args.secret else getpass("Enter the secret: ")
        manager.add_secret(args.add, secret, args.digits, args.interval)
    elif args.delete:
        manager.delete_secret(args.delete)
    elif args.generate is not None:
        if args.generate == "":
            service = select_service_interactively(manager)
            if service is None:
                return
        else:
            service = args.generate

        otp = manager.generate_otp(service)
        if args.copy:
            text_to_clipboard(otp)
    elif args.list:
        manager.list_secrets()
    elif args.import_file:
        manager.import_aegis_json(args.import_file)
    elif args.rename:
        manager.rename_service(args.rename[0], args.rename[1])
