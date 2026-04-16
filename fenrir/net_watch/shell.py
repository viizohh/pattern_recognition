"""Interactive shell for Fenrir

This module provides the interactive command-line interface for Fenrir.
Users must enter this shell before they can use sniff commands (security feature).
"""

import cmd
import shlex
import sys
from colorama import Fore, Style, init

init(autoreset=True)

# ASCII art for Fenrir
FENRIR_ASCII = f"""{Fore.CYAN}
     ___           ___           ___           ___                       ___
    /\__\\         /\__\\         /\  \\         /\  \\                     /\  \\
   /:/ _/_       /:/ _/_        \:\  \\       /::\  \\       ___         /::\  \\
  /:/ /\__\\     /:/ /\__\\        \:\  \\     /:/\:\__\\     /\__\\       /:/\:\__\\
 /:/ /:/  /    /:/ /:/ _/_   _____\:\  \\   /:/ /:/  /    /:/__/      /:/ /:/  /
/:/_/:/  /    /:/_/:/ /\__\\ /::::::::\__\\ /:/_/:/__/___ /::\  \\     /:/_/:/__/___
\:\/:/  /     \:\/:/ /:/  / \:\~~\~~\/__/ \:\/:::::/  / \/\:\  \\__  \:\/:::::/  /
 \::/__/       \::/_/:/  /   \:\  \\        \::/~~/~~~~   ~~\:\/\__\\  \::/~~/~~~~
  \:\  \\        \:\/:/  /     \:\  \\        \:\~~\\          \::/  /   \:\~~\\
   \:\__\\        \::/  /       \:\__\\        \:\__\\         /:/  /     \:\__\\
    \/__/         \/__/         \/__/         \/__/         \/__/       \/__/
{Style.RESET_ALL}"""

GOODBYE_ASCII = f"""{Fore.YELLOW}
    ,---,.                 ,---,.
  ,'  .'  \\       ,---,  ,'  .' |
,---.' .' |      /_ ./|,---.'   |
|   |  |: |,---, |  ' :|   |   .'
:   :  :  /___/ \\.  : |:   :  |-,
:   |    ; .  \\  \\ ,' ':   |  ;/|
|   :     \\ \\  ;  `  ,'|   :   .'
|   |   . |  \\  \\    ' |   |  |-,
'   :  '; |   '  \\   | '   :  ;/|
|   |  | ;     \\  ;  ; |   |    \\
|   :   /       :  \\  \\|   :   .'
|   | ,'         \\  ' ;|   | ,'
`----'            `--` `----'
{Style.RESET_ALL}"""

class FenrirShell(cmd.Cmd):
    """Interactive shell for Fenrir network monitoring tool

    This shell provides a security layer - users must type 'fenrir' to enter
    the shell before they can run sniff commands. This prevents unauthorized
    network monitoring on shared computers.
    """

    # Message shown when shell starts
    intro = FENRIR_ASCII + \
            f"\n{Fore.GREEN}Welcome to Fenrir v1.0 - Network Security Scanner{Style.RESET_ALL}\n" \
            f"Type 'help' to see available commands\n"

    # Command prompt shown to user
    prompt = f"{Fore.YELLOW}fenrir> {Style.RESET_ALL}"

    def do_sniff(self, arg):
        """
        Sniff network traffic

        Usage:
          sniff live --iface INTERFACE [OPTIONS]
          sniff pcap FILE [OPTIONS]

        Examples:
          sniff live --iface en0 --show-all
          sniff live --iface en0 --device 10.101.7.164 --show-all --ai
          sniff pcap capture.pcap --show-all --ai

        Options:
          --iface TEXT      Network interface (required for live)
          --device TEXT     Filter for specific device IP
          --show-all        Show ALL traffic (like Wireshark)
          --alerts-only     Only show warnings and alerts
          --verbose         Show detailed information
          --ai              Enable AI analysis (requires ANTHROPIC_API_KEY)
        """
        if not arg:
            print(f"{Fore.RED}Error: sniff requires a subcommand (live or pcap){Style.RESET_ALL}")
            print("Usage: sniff live --iface INTERFACE [OPTIONS]")
            print("       sniff pcap FILE [OPTIONS]")
            return

        try:
            # Import capture functions (done here to avoid circular imports)
            from net_watch.cli import run_live_capture, run_pcap_analysis

            # Split arguments using shlex to handle quoted strings properly
            args = shlex.split(arg)

            if not args:
                print(f"{Fore.RED}Error: sniff requires a subcommand{Style.RESET_ALL}")
                return

            # First argument is the subcommand (live or pcap)
            subcommand = args[0]
            rest_args = args[1:]

            if subcommand == 'live':
                # Live packet capture mode
                options = self._parse_options(rest_args)

                # Interface is required for live capture
                if 'iface' not in options:
                    print(f"{Fore.RED}Error: --iface is required for live capture{Style.RESET_ALL}")
                    print("Usage: sniff live --iface INTERFACE [OPTIONS]")
                    return

                run_live_capture(
                    iface=options.get('iface'),
                    device=options.get('device'),
                    show_all=options.get('show-all', False),
                    verbose=options.get('verbose', False),
                    alerts_only=options.get('alerts-only', False),
                    enable_ai=options.get('ai', False)
                )

            elif subcommand == 'pcap':
                # PCAP file analysis mode
                if not rest_args:
                    print(f"{Fore.RED}Error: pcap requires a file path{Style.RESET_ALL}")
                    print("Usage: sniff pcap FILE [OPTIONS]")
                    return

                # First argument after 'pcap' is the file path
                pcap_file = rest_args[0]
                options = self._parse_options(rest_args[1:])

                # Analyze the pcap file with parsed options
                run_pcap_analysis(
                    pcap_file=pcap_file,
                    device=options.get('device'),
                    show_all=options.get('show-all', False),
                    verbose=options.get('verbose', False),
                    alerts_only=options.get('alerts-only', False),
                    enable_ai=options.get('ai', False)
                )
            else:
                print(f"{Fore.RED}Error: Unknown subcommand '{subcommand}'{Style.RESET_ALL}")
                print("Available subcommands: live, pcap")

        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            print("\n\nCapture stopped.")
        except Exception as e:
            # Catch and display any other errors
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def _parse_options(self, args):
        """Parse command-line style options into a dictionary

        Converts arguments like ['--iface', 'en0', '--show-all'] into
        {'iface': 'en0', 'show-all': True}
        """
        options = {}
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith('--'):
                # Remove the '--' prefix to get the key name
                key = arg[2:]

                if i + 1 < len(args) and not args[i + 1].startswith('--'):
                    # Next argument is the value (e.g., --iface en0)
                    options[key] = args[i + 1]
                    i += 2
                else:
                    # It's a boolean flag (e.g., --show-all)
                    options[key] = True
                    i += 1
            else:
                # Not an option, skip it
                i += 1
        return options

    def do_help(self, arg):
        """Show help information"""
        if arg == 'sniff':
            self.do_sniff('')
        else:
            super().do_help(arg)
            print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
            print("║                  FENRIR COMMAND REFERENCE                ║")
            print("╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
            print(f"{Fore.GREEN}Available Commands:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}sniff{Style.RESET_ALL}     Monitor network traffic (live or pcap)")
            print(f"  {Fore.YELLOW}help{Style.RESET_ALL}      Show this help message")
            print(f"  {Fore.YELLOW}quit{Style.RESET_ALL}      Exit Fenrir")
            print(f"  {Fore.YELLOW}exit{Style.RESET_ALL}      Exit Fenrir")
            print(f"\n{Fore.GREEN}Quick Examples:{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}fenrir>{Style.RESET_ALL} sniff live --iface en0")
            print(f"  {Fore.CYAN}fenrir>{Style.RESET_ALL} sniff live --iface en0 --ai")
            print(f"  {Fore.CYAN}fenrir>{Style.RESET_ALL} sniff pcap capture.pcap --ai")
            print(f"\n{Fore.GREEN}For detailed help on a command:{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}fenrir>{Style.RESET_ALL} help sniff\n")

    def do_quit(self, arg):
        """Exit Fenrir"""
        print(GOODBYE_ASCII)
        print(f"{Fore.CYAN}Until we hunt again...{Style.RESET_ALL}\n")
        return True

    def do_exit(self, arg):
        """Exit Fenrir"""
        return self.do_quit(arg)

    def do_EOF(self, arg):
        """Handle Ctrl+D"""
        print()  # New line
        return self.do_quit(arg)

    def emptyline(self):
        """Do nothing on empty line"""
        pass

    def default(self, line):
        """Handle unknown commands"""
        print(f"{Fore.RED}Unknown command: {line}{Style.RESET_ALL}")
        print("Type 'help' for available commands.")


def start_shell():
    """Start the interactive Fenrir shell"""
    FenrirShell().cmdloop()
