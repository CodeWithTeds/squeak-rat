VIOLET = "#8b5cf6"
VIOLET_DIM = "#a78bfa"
VIOLET_ACC = "#7c3aed"

def render_banner(with_image=True, compact=False):
    # Python violet banner (ANSI) — approximates PHP RatBanner.php:32
    # If compact, single line
    if compact:
        print("\033[38;2;139;92;246m🐀 RAT\033[0m \033[90mLaravel Application Security & Behavior Analyzer\033[0m")
        return
    # Block-letter fallback (no GD inline image needed in python terminal)
    # We show violet block + wordmark
    print("\033[38;2;139;92;246m  ██████╗  █████╗ ████████╗\033[0m  \033[38;2;167;139;250m🐀 RAT\033[0m \033[90m— Python-native Analyzer\033[0m")
    print("\033[38;2;139;92;246m  ██╔══██╗██╔══██╗╚══██╔══╝\033[0m  \033[38;2;167;139;250mRAT follows the trail.\033[0m \033[90m(python)\033[0m")
    print("\033[38;2;139;92;246m  ██████╔╝███████║   ██║\033[0m")
    print("\033[38;2;139;92;246m  ██╔══██╗██╔══██║   ██║\033[0m")
    print("\033[38;2;139;92;246m  ██║  ██║██║  ██║   ██║\033[0m")
    print("\033[38;2;139;92;246m  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝\033[0m")
    print(f"  \033[38;2;124;58;237m{'─'*58}\033[0m")
