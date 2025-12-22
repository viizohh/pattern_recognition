"""Interactive shell for hound

This module provides the interactive command-line interface for hound.
Users must enter this shell before they can use sniff commands (security feature).
"""

import cmd
import shlex
import sys
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

# ASCII art banner displayed when entering the shell
BANNER = """
.__                             .___
|  |__   ____  __ __  ____    __| _/
|  |  \ /  _ \|  |  \/    \  / __ |
|   Y  (  <_> )  |  /   |  \/ /_/ |
|___|  /\____/|____/|___|  /\____ |
     \/                  \/      \/
"""


class HoundShell(cmd.Cmd):
    """Interactive shell for hound network monitoring tool

    This shell provides a security layer - users must type 'hound' to enter
    the shell before they can run sniff commands. This prevents unauthorized
    network monitoring on shared computers.
    """

    # Message shown when shell starts
    intro = f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}\n" \
            f"{Fore.GREEN}hound v0.1.0 - Network Monitoring Tool{Style.RESET_ALL}\n" \
            f"Type 'help' or '?' for commands. Type 'quit' or 'exit' to leave.\n"

    # Command prompt shown to user
    prompt = f"{Fore.YELLOW}hound> {Style.RESET_ALL}"

    def do_sniff(self, arg):
        """
        Sniff network traffic

        Usage:
          sniff live --iface INTERFACE [OPTIONS]
          sniff pcap FILE [OPTIONS]

        Examples:
          sniff live --iface en0 --show-all
          sniff live --iface en0 --device 10.101.7.164 --show-all
          sniff pcap capture.pcap --show-all

        Options:
          --iface TEXT      Network interface (required for live)
          --device TEXT     Filter for specific device IP
          --show-all        Show ALL traffic (like Wireshark)
          --alerts-only     Only show warnings and alerts
          --verbose         Show detailed information
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
                    alerts_only=options.get('alerts-only', False)
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
                    alerts_only=options.get('alerts-only', False)
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

    def do_dig(self, arg):
        """
        Perform passive OSINT investigation on a domain

        Usage:
          dig DOMAIN [OPTIONS]

        Examples:
          dig example.com
          dig example.com --format json
          dig example.com --output results.json
          dig example.com --keywords "security,press,admin"
          dig example.com --keywords-file keywords.txt
          dig example.com --max-pages 6 --timeout 10
          dig example.com --polite
          dig example.com --format json --output results.json --keywords "security,admin"

        Options:
          --format FORMAT           Output format: table (default) or json
          --output FILE             Save results to JSON file
          --keywords LIST           Comma-separated keywords for email guessing
          --keywords-file FILE      Load keywords from file
          --max-pages N             Maximum web pages to scrape (default: 10)
          --timeout N               Request timeout in seconds (default: 10)
          --delay N                 Delay between requests in seconds (default: 1)
          --polite                  Enable polite mode (3+ second delays)
        """
        # Check if user provided a domain
        if not arg:
            print(f"{Fore.RED}Error: dig requires a domain{Style.RESET_ALL}")
            print("Usage: dig DOMAIN [OPTIONS]")
            print("Example: dig example.com")
            return

        try:
            # Import OSINT orchestrator (done here to avoid circular imports)
            from net_watch.osint.cli import OSINTOrchestrator

            # Split arguments
            args = shlex.split(arg)

            if not args:
                print(f"{Fore.RED}Error: dig requires a domain{Style.RESET_ALL}")
                return

            # First argument is the domain
            domain = args[0]
            rest_args = args[1:]

            # Parse options
            options = self._parse_options(rest_args)

            # Extract options with defaults
            format_type = options.get('format', 'table')
            output_file = options.get('output', None)
            keywords_str = options.get('keywords', None)
            keywords_file = options.get('keywords-file', None)
            max_pages = int(options.get('max-pages', 10))
            timeout = int(options.get('timeout', 10))
            delay = float(options.get('delay', 1.0))
            polite = options.get('polite', False)

            # Parse keywords if provided
            keywords = None
            if keywords_str:
                keywords = [k.strip() for k in keywords_str.split(',')]

            # Create orchestrator
            orchestrator = OSINTOrchestrator(
                timeout=timeout,
                max_pages=max_pages,
                delay=delay,
                polite=polite
            )

            # Run investigation
            orchestrator.investigate(
                domain=domain,
                keywords=keywords,
                keywords_file=keywords_file,
                format=format_type,
                output_file=output_file
            )

        except KeyboardInterrupt:
            print("\n\nInvestigation stopped.")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            import traceback
            if '--debug' in arg:
                traceback.print_exc()

    def do_fetch(self, arg):
        """
        Check for data breaches (ETHICAL USE ONLY)

        Usage:
          fetch -email EMAIL
          fetch -password PASSWORD
          fetch -domain DOMAIN
          fetch -username USERNAME
          fetch -phone PHONE

        Examples:
          fetch -email test@example.com
          fetch -password MyPassword123
          fetch -domain example.com
          fetch --help

        Options:
          -e, --email EMAIL         Check email address for breaches
          -p, --password PASSWORD   Check password against HIBP (k-anonymity)
          -d, --domain DOMAIN       Check domain for breaches
          -u, --username USERNAME   Check breaches with username data
          -ph, --phone PHONE        Check breaches with phone data
          --format FORMAT           Output format: table (default) or json
          -o, --output FILE         Save report to file
          --no-banner               Suppress ethics banner
        """
        # Check if user wants help
        if not arg or arg.strip() in ['-h', '--help']:
            from net_watch.breach.cli import BreachCLI
            cli = BreachCLI()
            cli.show_help()
            return

        try:
            # Import breach CLI orchestrator
            from net_watch.breach.cli import BreachCLI

            # Create CLI instance
            cli = BreachCLI()

            # Execute the fetch command
            cli.execute(arg)

        except KeyboardInterrupt:
            print("\n\nFetch stopped.")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            import traceback
            if '--debug' in arg:
                traceback.print_exc()

    def do_help(self, arg):
        """Show help information"""
        if arg == 'sniff':
            self.do_sniff('')
        elif arg == 'dig':
            self.do_dig('')
        elif arg == 'fetch':
            self.do_fetch('')
        else:
            super().do_help(arg)
            print("\nAvailable commands:")
            print("  sniff     Sniff network traffic (live or pcap)")
            print("  dig       Passive OSINT investigation on a domain")
            print("  fetch     Check for data breaches (ethical use only)")
            print("  help      Show this help message")
            print("  quit      Exit hound")
            print("  exit      Exit hound")

    def do_quit(self, arg):
        """Exit hound"""
        print(f"\n{Fore.CYAN}Goodbye! 🐕{Style.RESET_ALL}")
        return True

    def do_exit(self, arg):
        """Exit hound"""
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
    """Start the interactive hound shell"""
    HoundShell().cmdloop()
