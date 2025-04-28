"""
Display formatting utilities for the GitLab Repository Analyzer CLI.
Provides consistent UI elements and formatting for the interactive interface.
"""

import os
import sys
import time
from typing import List, Dict, Any


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner() -> None:
    """Print the application banner."""
    banner = """
 ██████╗ ██╗████████╗██╗      █████╗ ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
██╔════╝ ██║╚══██╔══╝██║     ██╔══██╗██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
██║  ███╗██║   ██║   ██║     ███████║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██║   ██║██║   ██║   ██║     ██╔══██║██╔══██╗    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
╚██████╔╝██║   ██║   ███████╗██║  ██║██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
                                                                                                                  
Repository Technology & Ecosystem Analyzer
v1.0.0
"""
    print(banner)


def print_section_header(title: str) -> None:
    """
    Print a section header.
    
    Args:
        title: Section title
    """
    terminal_width = _get_terminal_width()
    padding = max(0, terminal_width - len(title) - 6)
    half_padding = padding // 2
    
    print("\n" + "=" * terminal_width)
    print(" " * half_padding + f"[ {title} ]" + " " * (padding - half_padding))
    print("=" * terminal_width + "\n")


def print_error(message: str) -> None:
    """
    Print an error message.
    
    Args:
        message: Error message
    """
    print(f"\n❌ ERROR: {message}")


def print_warning(message: str) -> None:
    """
    Print a warning message.
    
    Args:
        message: Warning message
    """
    print(f"\n⚠️  WARNING: {message}")


def print_success(message: str) -> None:
    """
    Print a success message.
    
    Args:
        message: Success message
    """
    print(f"\n✅ SUCCESS: {message}")


def print_info(message: str) -> None:
    """
    Print an info message.
    
    Args:
        message: Info message
    """
    print(f"\nℹ️  INFO: {message}")


def print_progress_bar(current: int, total: int, prefix: str = "", suffix: str = "", length: int = 50) -> None:
    """
    Print a progress bar.
    
    Args:
        current: Current progress value
        total: Total value
        prefix: Text before the progress bar
        suffix: Text after the progress bar
        length: Length of the progress bar
    """
    percent = min(100, (current / total) * 100)
    filled_length = int(length * current // total)
    bar = "█" * filled_length + "-" * (length - filled_length)
    
    # Clear current line and print progress bar
    sys.stdout.write("\r")
    sys.stdout.write(f"{prefix} |{bar}| {percent:.1f}% {suffix}")
    sys.stdout.flush()
    
    # Print new line on complete
    if current == total:
        print()


def print_table(headers: List[str], rows: List[List[str]], title: str = None) -> None:
    """
    Print a formatted table.
    
    Args:
        headers: Table headers
        rows: Table rows (list of lists)
        title: Optional table title
    """
    if not headers or not rows:
        return
        
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Add padding
    col_widths = [width + 2 for width in col_widths]
    
    # Calculate total width
    total_width = sum(col_widths) + len(headers) - 1
    
    # Print title if provided
    if title:
        print_section_header(title)
    
    # Print headers
    header_row = "│"
    for i, header in enumerate(headers):
        header_row += f" {header.ljust(col_widths[i] - 2)} │"
    
    separator = "├" + "┼".join("─" * width for width in col_widths) + "┤"
    top_border = "┌" + "┬".join("─" * width for width in col_widths) + "┐"
    bottom_border = "└" + "┴".join("─" * width for width in col_widths) + "┘"
    
    print(top_border)
    print(header_row)
    print(separator)
    
    # Print rows
    for row in rows:
        row_str = "│"
        for i, cell in enumerate(row):
            if i < len(col_widths):
                row_str += f" {str(cell).ljust(col_widths[i] - 2)} │"
        print(row_str)
    
    print(bottom_border)


def print_tree(tree: Dict[str, Any], prefix: str = "", is_last: bool = True, title: str = None) -> None:
    """
    Print a tree structure.
    
    Args:
        tree: Dictionary representing tree structure
        prefix: Prefix for current level
        is_last: Whether current node is the last in its level
        title: Optional tree title
    """
    if title:
        print_section_header(title)
    
    if not tree:
        return
        
    # Print root
    root = next(iter(tree))
    print(f"{prefix}{'└── ' if is_last else '├── '}{root}")
    
    # Prepare prefix for children
    prefix_ext = "    " if is_last else "│   "
    
    # If value is a dictionary, process as subtree
    if isinstance(tree[root], dict):
        items = list(tree[root].items())
        for i, (key, val) in enumerate(items):
            is_last_child = i == len(items) - 1
            sub_tree = {key: val}
            print_tree(sub_tree, prefix + prefix_ext, is_last_child)
    # If value is a list, print each item
    elif isinstance(tree[root], list):
        for i, item in enumerate(tree[root]):
            is_last_child = i == len(tree[root]) - 1
            if isinstance(item, dict):
                for k, v in item.items():
                    sub_tree = {k: v}
                    print_tree(sub_tree, prefix + prefix_ext, is_last_child)
            else:
                print(f"{prefix}{prefix_ext}{'└── ' if is_last_child else '├── '}{item}")
    # For scalar values
    else:
        print(f"{prefix}{prefix_ext}└── {tree[root]}")


def _get_terminal_width() -> int:
    """
    Get terminal width or a default value.
    
    Returns:
        Terminal width
    """
    try:
        return os.get_terminal_size().columns
    except (AttributeError, OSError):
        return 80  # Default width


def print_spinner(message: str, seconds: float) -> None:
    """
    Display a spinner for the specified number of seconds.
    
    Args:
        message: Message to display with spinner
        seconds: Number of seconds to display spinner
    """
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + seconds
    
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{message} {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write(f"\r{message} ✓{' ' * 10}\n")


def loading_indicator(iterable, prefix: str = "", suffix: str = "", length: int = 50):
    """
    Generator that wraps an iterable with a progress bar.
    
    Args:
        iterable: Iterable to process
        prefix: Text before the progress bar
        suffix: Text after the progress bar
        length: Length of the progress bar
        
    Yields:
        Items from the original iterable
    """
    total = len(iterable) if hasattr(iterable, '__len__') else None
    
    if total is None:
        # For iterables without len, just show a spinner
        for i, item in enumerate(iterable):
            sys.stdout.write(f"\r{prefix} Processing item {i+1} {suffix}")
            sys.stdout.flush()
            yield item
        print()
    else:
        # For iterables with known length, show a progress bar
        for i, item in enumerate(iterable):
            print_progress_bar(i+1, total, prefix, suffix, length)
            yield item
