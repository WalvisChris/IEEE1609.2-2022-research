from typing import List
from pyasn1.type import univ
import os

COLORS = {
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_black": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m"
}

RESET = "\033[0m"

class TerminalInterface:
    def clear(self):
        os.system('cls')

    def text(self, text: str, color="white") -> None:
        color_code = COLORS.get(color.lower(), COLORS["white"])
        print(f"{color_code}{text}{RESET}")

    def input(self, prompt: str, color="white") -> str:
        color_code = COLORS.get(color.lower(), COLORS["white"])
        return input(f"{color_code}{prompt}{RESET}")

    def title(self, title: str, title_color="white", border_color="white"):
        title_color_code = COLORS.get(title_color.lower(), COLORS["white"])
        border_color_code = COLORS.get(border_color.lower(), COLORS["white"])
        
        WIDTH = len(title) + 10
        
        print(f"{border_color_code}{WIDTH*"="}{RESET}")
        print(f"{5*" "}{title_color_code}{title}{RESET}")
        print(f"{border_color_code}{WIDTH*"="}{RESET}")
    
    def textbox(self, title: str, title_color="white", items: List[str] = None, list_color="white", border_color="white", numbered: bool = False):
        if items is None:
            items = []

        title_color_code = COLORS.get(title_color.lower(), COLORS["white"])
        list_color_code = COLORS.get(list_color.lower(), COLORS["white"])
        border_color_code = COLORS.get(border_color.lower(), COLORS["white"])

        if numbered:
            numbered_items = [f"{i+1}. {item}" for i, item in enumerate(items)]
        else:
            numbered_items = items

        all_lines = [title] + numbered_items
        WIDTH = max(len(line) for line in all_lines) + 4  # +4 for padding

        print(f"{border_color_code}╭{'─' * WIDTH}╮{RESET}")

        print(f"{border_color_code}│ {title_color_code}{title.ljust(WIDTH - 2)}{border_color_code} │{RESET}")

        for sentence in numbered_items:
            print(f"{border_color_code}│ {list_color_code}{sentence.ljust(WIDTH - 2)}{border_color_code} │{RESET}")

        print(f"{border_color_code}╰{'─' * WIDTH}╯{RESET}")

    def demoLog(self, title: str, text: str, title_color="white", text_color="white"):
        title_color_code = COLORS.get(title_color.lower(), COLORS["white"])
        text_color_code = COLORS.get(text_color.lower(), COLORS["white"])
        print(f"[{title_color_code}{title}{RESET}]:\n{text_color_code}{text}{RESET}")
    
    def empty(self, lines: int = 1):
        print(lines*"\n")
    
    def displayASN1(self, obj, prefix='', is_last=True, depth=0):
        branch = '└ ' if is_last else '├ '
        name = obj.__class__.__name__

        # Kies kleur op basis van depth
        color_list = ["green", "blue", "yellow", "magenta", "cyan", "red"]  # kan uitbreiden
        color = COLORS[color_list[depth % len(color_list)]]

        # Functie om printen met kleur
        def cprint(text):
            print(f"{color}{text}{RESET}")

        # Sequence of Set
        if isinstance(obj, (univ.Sequence, univ.Set)):
            cprint(f"{prefix}{branch}{name}:")
            n = len(obj.componentType)
            for i, component in enumerate(obj.componentType.namedTypes):
                field_name = component.name
                is_last_field = (i == n - 1)
                new_prefix = prefix + ('    ' if is_last else '│   ')
                try:
                    self.displayASN1(obj[field_name], new_prefix, is_last_field, depth + 1)
                except Exception as e:
                    cprint(f"{new_prefix}└ <Error accessing {field_name}: {e}>")

        # Choice
        elif isinstance(obj, univ.Choice):
            cprint(f"{prefix}{branch}{name}:")
            new_prefix = prefix + ('    ' if is_last else '│   ')
            if obj.hasValue():
                try:
                    chosen_name = obj.getName()
                    self.displayASN1(obj[chosen_name], new_prefix, True, depth + 1)
                except Exception as e:
                    cprint(f"{new_prefix}└ <Error getting choice: {e}>")
            else:
                cprint(f"{new_prefix}└ <Not chosen>")

        # Basistypes
        else:
            if hasattr(obj, 'hasValue') and obj.hasValue():
                cprint(f"{prefix}{branch}{name} = {obj.prettyPrint()}")
            else:
                cprint(f"{prefix}{branch}{name} = <empty>")