from rich.console import Console
from rich.align import Align
from rich.panel import Panel
from rich.text import Text

from src.modules.utils import get_terminal_width


# https://patorjk.com/software/taag/
def print_banner(console: Console) -> None:
    width: int = get_terminal_width()
    height: int = 5

    banner: str = (
            "╔═╗┬ ┬┌┬┐┌─┐╔═╗╦ ╦╔╗╔  ╔═╗┬ ┬┬┌┬┐┌─┐"
            "\n╠═╣│ │ │ │ │╠═╝║║║║║║  ╚═╗│ ││ │ ├┤"
            "\n╩ ╩└─┘ ┴ └─┘╩  ╚╩╝╝╚╝  ╚═╝└─┘┴ ┴ └─┘"
        )

    if width > 90:
        height: int = 8
        banner: str = (
            r"     ___           __          ____  _"
            r"       __ _   __   _____         _  __""\n"
            r"    /   |  __  __ / /_ ____   / __ \|"
            r" |     / // | / /  / ___/ __  __ (_)/ /_ ___""\n"
            r"   / /| | / / / // __// __ \ / /_/ /| | /| /"
            r" //  |/ /   \__ \ / / / // // __// _ \\""\n"
            r"  / ___ |/ /_/ // /_ / /_/ // ____/ | |/ |/ "
            r"// /|  /   ___/ // /_/ // // /_ /  __/""\n"
            r" /_/  |_|\____/ \__/ \____//_/      |__/|__//"
            r"_/ |_/   /____/ \____//_/ \__/ \___/"
        )

    panel = Panel(
        Align(
            Text(
                banner,
                justify="center",
                style="blue"
            ),
            vertical="middle",
            align="center",
        ),
        width=width,
        height=height,
        subtitle="by GamehunterKaan (https://auto.pwnspot.com)",
    )
    console.print(panel)
