"""Interactive shell for vcu

This module provides the interactive command-line interface for vcu.
Users must enter this shell before they can use sniff commands (security feature).
"""

import cmd
import shlex
import sys
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

class VCUShell(cmd.Cmd):
    """Interactive shell for vcu network monitoring tool

    This shell provides a security layer - users must type 'vcu' to enter
    the shell before they can run sniff commands. This prevents unauthorized
    network monitoring on shared computers.
    """

    # Message shown when shell starts
    intro = f"{Fore.GREEN}vcu v0.1.0 - Network Monitoring Tool{Style.RESET_ALL}\n" \
            f"Type 'help' or '?' for commands. Type 'quit' or 'exit' to leave.\n"

    # Command prompt shown to user
    prompt = f"{Fore.YELLOW}vcu> {Style.RESET_ALL}"

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
        # Check if user provided a subcommand
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

                # Start live capture with parsed options
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

                # Check if this option has a value or is just a flag
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
            print("\nAvailable commands:")
            print("  sniff     Sniff network traffic (live or pcap)")
            print("  help      Show this help message")
            print("  quit      Exit vcu")
            print("  exit      Exit vcu")

    def do_quit(self, arg):
        """Exit vcu"""
        print(f"\n{Fore.CYAN}Goodbye! 🐏{Style.RESET_ALL}")
        return True

    def do_exit(self, arg):
        """Exit vcu"""
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
    """Start the interactive vcu shell"""
    VCUShell().cmdloop()
