"""
Input helper functions for the GitLab Repository Analyzer CLI.
Provides utilities for user input in the interactive interface.
"""

from typing import List, Tuple, Dict, Any, Optional
import sys


def select_multiple_items(items: List[str], prompt: str) -> List[int]:
    """
    Allow user to select multiple items from a list.
    
    Args:
        items: List of items to choose from
        prompt: Prompt message to display
        
    Returns:
        List of selected indices
    """
    if not items:
        print("No items available to select.")
        return []
        
    selected_indices = []
    
    print(f"\n{prompt} (enter numbers separated by commas, 'all' for all, or empty to cancel):")
    
    for i, item in enumerate(items, 1):
        print(f"{i}. {item}")
    
    choice = input("\nSelection: ").strip()
    
    if not choice:
        return []
        
    if choice.lower() == 'all':
        return list(range(len(items)))
    
    try:
        # Split by commas and handle ranges (e.g., "1-3,5,7-9")
        parts = choice.split(',')
        
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                # Handle range
                start, end = part.split('-')
                if start.isdigit() and end.isdigit():
                    start_idx = int(start) - 1
                    end_idx = int(end) - 1
                    
                    if 0 <= start_idx < len(items) and 0 <= end_idx < len(items):
                        selected_indices.extend(range(start_idx, end_idx + 1))
            elif part.isdigit():
                # Handle single number
                idx = int(part) - 1
                if 0 <= idx < len(items):
                    selected_indices.append(idx)
        
        # Remove duplicates and sort
        selected_indices = sorted(set(selected_indices))
        
        if not selected_indices:
            print("No valid selections made.")
            
    except Exception as e:
        print(f"Error processing selection: {str(e)}")
        return []
    
    # Show what was selected
    if selected_indices:
        print("\nSelected:")
        for idx in selected_indices:
            print(f"- {items[idx]}")
    
    return selected_indices


def toggle_multiple_options(options: List[Tuple[str, bool]]) -> List[Tuple[str, bool]]:
    """
    Allow user to toggle multiple boolean options.
    
    Args:
        options: List of (option name, current state) tuples
        
    Returns:
        Updated list of (option name, new state) tuples
    """
    print("\nCurrent options (enter numbers to toggle, comma separated, or empty to keep current):")
    
    for i, (option, state) in enumerate(options, 1):
        status = "✓" if state else "✗"
        print(f"{i}. {option} [{status}]")
    
    choice = input("\nToggle options: ").strip()
    
    if not choice:
        return options
    
    # Make a copy of options to modify
    result = list(options)
    
    try:
        # Handle comma-separated values and ranges
        parts = choice.split(',')
        indices_to_toggle = []
        
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                # Handle range
                start, end = part.split('-')
                if start.isdigit() and end.isdigit():
                    start_idx = int(start) - 1
                    end_idx = int(end) - 1
                    
                    if 0 <= start_idx < len(options) and 0 <= end_idx < len(options):
                        indices_to_toggle.extend(range(start_idx, end_idx + 1))
            elif part.isdigit():
                # Handle single number
                idx = int(part) - 1
                if 0 <= idx < len(options):
                    indices_to_toggle.append(idx)
        
        # Remove duplicates
        indices_to_toggle = list(set(indices_to_toggle))
        
        # Toggle selected options
        for idx in indices_to_toggle:
            option_name, current_state = result[idx]
            result[idx] = (option_name, not current_state)
        
    except Exception as e:
        print(f"Error processing selection: {str(e)}")
    
    # Show updated options
    print("\nUpdated options:")
    for i, (option, state) in enumerate(result, 1):
        status = "✓" if state else "✗"
        print(f"{i}. {option} [{status}]")
    
    return result


def configure_custom_patterns(existing_patterns: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Allow user to define custom detection patterns.
    
    Args:
        existing_patterns: List of existing custom patterns
        
    Returns:
        Updated list of custom patterns
    """
    patterns = existing_patterns.copy() if existing_patterns else []
    
    # Display existing patterns if any
    if patterns:
        print("\nExisting custom patterns:")
        for i, pattern in enumerate(patterns, 1):
            print(f"{i}. {pattern['name']} ({pattern['category']}) - {pattern['file_pattern']}")
    
    # Add new patterns
    while True:
        print("\n--- Custom Pattern Configuration ---")
        name = input("Pattern name (or empty to finish): ").strip()
        
        if not name:
            break
        
        file_pattern = input("File pattern (e.g. '*.tf' or 'config/*.yml'): ").strip()
        
        content_pattern = input("Content pattern to match: ").strip()
        
        # Category selection
        print("\nSelect category:")
        categories = [
            "frontend", "backend", "database", "infrastructure", "cicd", "custom"
        ]
        
        for i, category in enumerate(categories, 1):
            print(f"{i}. {category}")
            
        cat_choice = input("Category (1-6): ").strip()
        
        try:
            category_idx = int(cat_choice) - 1
            if 0 <= category_idx < len(categories):
                category = categories[category_idx]
            else:
                category = "custom"
        except ValueError:
            category = "custom"
        
        # Create pattern
        patterns.append({
            'name': name,
            'file_pattern': file_pattern,
            'content_pattern': content_pattern,
            'category': category
        })
        
        print(f"Pattern '{name}' added successfully.")
        
        # Ask if user wants to add more
        if input("\nAdd another pattern? (y/n): ").lower() != 'y':
            break
    
    return patterns


def get_confirmation(prompt: str, default: bool = False) -> bool:
    """
    Get a yes/no confirmation from the user.
    
    Args:
        prompt: Question to ask
        default: Default response if user just presses Enter
        
    Returns:
        True for yes, False for no
    """
    default_text = "Y/n" if default else "y/N"
    response = input(f"{prompt} [{default_text}]: ").strip().lower()
    
    if not response:
        return default
        
    return response.startswith('y')


def get_input_with_default(prompt: str, default: str) -> str:
    """
    Get input with a default value.
    
    Args:
        prompt: Input prompt
        default: Default value if user just presses Enter
        
    Returns:
        User input or default value
    """
    response = input(f"{prompt} [{default}]: ").strip()
    
    if not response:
        return default
        
    return response


def get_choice_from_list(items: List[str], prompt: str, allow_empty: bool = False) -> Optional[int]:
    """
    Get user choice from a list of items.
    
    Args:
        items: List of items to choose from
        prompt: Prompt to display
        allow_empty: Whether to allow empty input
        
    Returns:
        Selected index or None if empty input is allowed and given
    """
    if not items:
        print("No items available.")
        return None
        
    print(f"\n{prompt}:")
    
    for i, item in enumerate(items, 1):
        print(f"{i}. {item}")
        
    if allow_empty:
        choice = input("\nSelect an option (or press Enter to cancel): ").strip()
        if not choice:
            return None
    else:
        choice = input("\nSelect an option: ").strip()
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(items):
            return idx
    except ValueError:
        print("Invalid input. Please enter a number.")
        return get_choice_from_list(items, prompt, allow_empty)
    
    print(f"Please enter a number between 1 and {len(items)}.")
    return get_choice_from_list(items, prompt, allow_empty)
