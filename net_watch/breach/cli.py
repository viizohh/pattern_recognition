"""CLI orchestrator for breach fetch command

Coordinates breach checking operations and output formatting.
"""

import argparse
import sys
from typing import Optional, Dict
from net_watch.breach.password_checker import PasswordChecker
from net_watch.breach.email_checker import EmailChecker
from net_watch.breach.formatter import BreachFormatter


class BreachCLI:
    """CLI orchestrator for breach checking commands"""

    def __init__(self):
        """Initialize CLI with checkers and formatter"""
        self.password_checker = PasswordChecker()
        self.email_checker = EmailChecker()
        self.formatter = BreachFormatter()

    def execute(self, args_string: str) -> Optional[str]:
        """Execute breach fetch command

        Args:
            args_string: Command line arguments as string

        Returns:
            Output string if JSON format requested, None otherwise
        """
        # Parse arguments
        parser = self._create_parser()

        try:
            # Split args_string into list for argparse
            args = args_string.split() if args_string else []
            parsed_args = parser.parse_args(args)
        except SystemExit:
            # argparse calls sys.exit on error, catch it
            return None

        # Validate that exactly one query type is specified
        query_types = [
            parsed_args.email,
            parsed_args.password,
            parsed_args.domain,
            parsed_args.username,
            parsed_args.phone
        ]

        if sum(x is not None for x in query_types) == 0:
            print("Error: No query type specified. Use -email, -password, -domain, -username, or -phone")
            print("Example: fetch -email test@example.com")
            return None

        if sum(x is not None for x in query_types) > 1:
            print("Error: Only one query type allowed per fetch command")
            return None

        # Route to appropriate checker
        result = None
        query_type = None
        query_value = None

        if parsed_args.email:
            query_type = 'email'
            query_value = parsed_args.email
            result = self.email_checker.check_email(query_value)

        elif parsed_args.password:
            query_type = 'password'
            query_value = parsed_args.password
            result = self.password_checker.check_password(query_value)

        elif parsed_args.domain:
            query_type = 'domain'
            query_value = parsed_args.domain
            result = self.email_checker.check_domain(query_value)

        elif parsed_args.username:
            query_type = 'username'
            query_value = parsed_args.username
            result = self.email_checker.check_username(query_value)

        elif parsed_args.phone:
            query_type = 'phone'
            query_value = parsed_args.phone
            result = self.email_checker.check_phone(query_value)

        if result is None:
            print("Error: Query execution failed")
            return None

        # Handle output format
        if parsed_args.format == 'json':
            json_output = self.formatter.format_as_json(result, query_value, query_type)

            # Save to file if requested
            if parsed_args.output:
                with open(parsed_args.output, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                print(f"Report saved to: {parsed_args.output}")
            else:
                print(json_output)

            return json_output
        else:
            # Table format (default)
            show_banner = not parsed_args.no_banner

            if query_type == 'password':
                self.formatter.format_password_result(result, show_banner=show_banner)
            else:
                # email, domain, username, phone all use email formatter
                self.formatter.format_email_result(result, show_banner=show_banner)

            # Save to file if requested
            if parsed_args.output:
                self.formatter.save_to_json(result, query_value, query_type)

        return None

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for fetch command

        Returns:
            Configured ArgumentParser
        """
        parser = argparse.ArgumentParser(
            prog='fetch',
            description='Check for data breaches (ETHICAL USE ONLY)',
            add_help=True
        )

        # Query type arguments (mutually exclusive)
        parser.add_argument('-e', '--email',
                          type=str,
                          help='Check email address for breaches')

        parser.add_argument('-p', '--password',
                          type=str,
                          help='Check password against HIBP (uses k-anonymity)')

        parser.add_argument('-d', '--domain',
                          type=str,
                          help='Check domain for breaches')

        parser.add_argument('-u', '--username',
                          type=str,
                          help='Check breaches that exposed username data')

        parser.add_argument('-ph', '--phone',
                          type=str,
                          help='Check breaches that exposed phone data')

        # Output format options
        parser.add_argument('--format',
                          type=str,
                          choices=['table', 'json'],
                          default='table',
                          help='Output format (default: table)')

        parser.add_argument('-o', '--output',
                          type=str,
                          help='Save report to file (auto-named for table, custom for JSON)')

        parser.add_argument('--no-banner',
                          action='store_true',
                          help='Suppress ethics banner')

        return parser

    def show_help(self):
        """Display help message"""
        parser = self._create_parser()
        parser.print_help()

        # Additional examples
        print("\n" + "="*60)
        print("EXAMPLES:")
        print("="*60)
        print("\nCheck email for breaches:")
        print("  fetch -email test@example.com")
        print("\nCheck password (uses HIBP k-anonymity, NO API KEY needed):")
        print("  fetch -password MyPassword123")
        print("\nCheck domain:")
        print("  fetch -domain example.com")
        print("\nCheck with JSON output:")
        print("  fetch -email test@example.com --format json")
        print("\nSave report to file:")
        print("  fetch -email test@example.com --output report.json")
        print("\n" + "="*60)
        print("DATA SOURCES:")
        print("="*60)
        print("* Passwords: HIBP Pwned Passwords API (free, no API key)")
        print("* Email/Domain: Local database of 14 major known breaches")
        print("               (DOMAIN-level only, not specific email addresses)")
        print("* Username/Phone: Breach metadata (not actual leaked data)")
        print("\nWARNING: ETHICAL USE ONLY - Check your own data or with permission")
        print("NOTE: For specific email address checking, use haveibeenpwned.com")
        print("="*60 + "\n")


def main():
    """Main entry point for standalone testing"""
    cli = BreachCLI()

    # Get args from command line
    import sys
    args_string = ' '.join(sys.argv[1:])

    if not args_string or args_string in ['-h', '--help']:
        cli.show_help()
    else:
        cli.execute(args_string)


if __name__ == '__main__':
    main()
