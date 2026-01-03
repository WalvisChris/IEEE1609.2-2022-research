from typing import List
from pyasn1.type import univ
import os

class TerminalInterface:
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
        "bright_white": "\033[97m",
        "vs_yellow": "\033[38;2;214;194;139m",
        "vs_purple": "\033[38;2;137;71;252m"
    }

    RESET = "\033[0m"

    def clear(self):
        os.system('cls')

    def text(self, text: str, color="white") -> None:
        color_code = self.COLORS.get(color.lower(), self.COLORS["white"])
        print(f"{color_code}{text}{self.RESET}")

    def input(self, prompt: str, color="white") -> str:
        color_code = self.COLORS.get(color.lower(), self.COLORS["white"])
        return input(f"{color_code}{prompt}{self.RESET}")

    def title(self, title: str, title_color="white", border_color="white"):
        title_color_code = self.COLORS.get(title_color.lower(), self.COLORS["white"])
        border_color_code = self.COLORS.get(border_color.lower(), self.COLORS["white"])

        WIDTH = len(title) + 10

        print(f"{border_color_code}{WIDTH*"="}{self.RESET}")
        print(f"{5*" "}{title_color_code}{title}{self.RESET}")
        print(f"{border_color_code}{WIDTH*"="}{self.RESET}")

    def textbox(self, title: str, title_color="white", items: List[str] = None, list_color="white", border_color="white", numbered: bool = False):
        if items is None:
            items = []

        title_color_code = self.COLORS.get(title_color.lower(), self.COLORS["white"])
        list_color_code = self.COLORS.get(list_color.lower(), self.COLORS["white"])
        border_color_code = self.COLORS.get(border_color.lower(), self.COLORS["white"])

        if numbered:
            numbered_items = [f"{i+1}. {item}" for i, item in enumerate(items)]
        else:
            numbered_items = items

        all_lines = [title] + numbered_items
        WIDTH = max(len(line) for line in all_lines) + 4  # +4 for padding

        print(f"{border_color_code}╭{'─' * WIDTH}╮{self.RESET}")

        print(f"{border_color_code}│ {title_color_code}{title.ljust(WIDTH - 2)}{border_color_code} │{self.RESET}")

        for sentence in numbered_items:
            print(f"{border_color_code}│ {list_color_code}{sentence.ljust(WIDTH - 2)}{border_color_code} │{self.RESET}")

        print(f"{border_color_code}╰{'─' * WIDTH}╯{self.RESET}")

    def demoLog(self, title: str, text: str, title_color="white", text_color="white"):
        title_color_code = self.COLORS.get(title_color.lower(), self.COLORS["white"])
        text_color_code = self.COLORS.get(text_color.lower(), self.COLORS["white"])
        print(f"[{title_color_code}{title}{self.RESET}]:\n{text_color_code}{text}{self.RESET}")

    def empty(self, lines: int = 1):
        print(lines*"\n")
    
    KEY_COLORS_BY_DEPTH = [
        "blue"
    ]

    DATATYPE_COLORS_BY_DEPTH = [
        "bright_green",
        "vs_purple"
    ]

    VALUE_COLORS_BY_DEPTH = [
        "vs_yellow",
        "white"
    ]

    def displayASN1(self, obj, prefix='', is_last=True, depth=0, field_name=None):
        """
        Robust ASN.1 tree printer with colors per depth and datatype display.
        """
        branch = '└ ' if is_last else '├ '

        # Kies kleuren per depth
        key_color = self.COLORS[self.KEY_COLORS_BY_DEPTH[depth % len(self.KEY_COLORS_BY_DEPTH)]]
        value_color = self.COLORS[self.VALUE_COLORS_BY_DEPTH[depth % len(self.VALUE_COLORS_BY_DEPTH)]]
        datatype_color = self.COLORS[self.DATATYPE_COLORS_BY_DEPTH[depth % len(self.DATATYPE_COLORS_BY_DEPTH)]]
        reset = self.RESET

        display_name = field_name if field_name else obj.__class__.__name__
        datatype_name = obj.__class__.__name__

        base = f"{prefix}{branch}"

        # ===== Sequence / Set =====
        if isinstance(obj, (univ.Sequence, univ.Set)):
            print(f"{base}{key_color}{display_name}{reset} ({datatype_color}{datatype_name}{reset}):")
            n = len(obj.componentType)
            for i, component in enumerate(obj.componentType.namedTypes):
                fname = component.name
                is_last_field = (i == n - 1)
                new_prefix = prefix + ('    ' if is_last else '│   ')
                try:
                    self.displayASN1(obj[fname], new_prefix, is_last_field, depth + 1, field_name=fname)
                except Exception as e:
                    print(f"{new_prefix}└ <Error accessing {fname}: {e}>")

        # ===== Choice =====
        elif isinstance(obj, univ.Choice):
            print(f"{base}{key_color}{display_name}{reset} ({datatype_color}{datatype_name}{reset}):")
            new_prefix = prefix + ('    ' if is_last else '│   ')
            if obj.hasValue():
                try:
                    chosen_name = obj.getName()
                    self.displayASN1(obj[chosen_name], new_prefix, True, depth + 1, field_name=chosen_name)
                except Exception as e:
                    print(f"{new_prefix}└ <Error getting choice: {e}>")
            else:
                print(f"{new_prefix}└ {value_color}<Not chosen>{reset}")

        # ===== Basistypes =====
        else:
            if hasattr(obj, 'hasValue') and obj.hasValue():
                print(
                    f"{base}"
                    f"{key_color}{display_name}{reset} "
                    f"({datatype_color}{datatype_name}{reset}) = "
                    f"{value_color}{obj.prettyPrint()}{reset}"
                )
            else:
                print(
                    f"{base}"
                    f"{key_color}{display_name}{reset} "
                    f"({datatype_color}{datatype_name}{reset}) = "
                    f"{value_color}<empty>{reset}"
                )

    def UpperHeader(self, text: str, text_color="white", border_color="white"):
        text_color_code = self.COLORS.get(text_color.lower(), self.COLORS["white"])
        border_color_code = self.COLORS.get(border_color.lower(), self.COLORS["white"])
        print(f"{border_color_code}[{text_color_code}{text.upper()}{border_color_code}]{self.RESET}")