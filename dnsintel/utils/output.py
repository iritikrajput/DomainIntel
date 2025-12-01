"""
Output formatting utilities for displaying results.
"""

from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def print_header(text: str) -> None:
    """
    Print a header with formatting.

    Args:
        text: Header text to display
    """
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}\n")


def print_success(text: str) -> None:
    """
    Print success message in green.

    Args:
        text: Message to display
    """
    print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")


def print_error(text: str) -> None:
    """
    Print error message in red.

    Args:
        text: Message to display
    """
    print(f"{Fore.RED}{text}{Style.RESET_ALL}")


def print_warning(text: str) -> None:
    """
    Print warning message in yellow.

    Args:
        text: Message to display
    """
    print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")


def print_info(text: str) -> None:
    """
    Print info message in default color.

    Args:
        text: Message to display
    """
    print(text)


def print_table(headers: list, rows: list) -> None:
    """
    Print data in table format.

    Args:
        headers: List of column headers
        rows: List of rows (each row is a list of values)
    """
    from tabulate import tabulate
    print(tabulate(rows, headers=headers, tablefmt="grid"))


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human-readable format.

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def truncate_text(text: str, max_length: int = 50) -> str:
    """
    Truncate text to specified length.

    Args:
        text: Text to truncate
        max_length: Maximum length

    Returns:
        Truncated text with ellipsis if needed
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

