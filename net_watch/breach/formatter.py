"""Output formatters for breach check results"""

import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from typing import Dict, Any


class BreachFormatter:
    """Format breach check results for display"""

    def __init__(self):
        """Initialize formatter"""
        self.console = Console()

    def print_ethics_banner(self):
        """Print ethical use banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║  HOUND BREACH CHECKER - Data Breach Intelligence              ║
║                                                               ║
║  WARNING: ETHICAL USE ONLY - Check Your Own Data             ║
║                                                               ║
║  Permitted uses:                                              ║
║  * Check your own email/password/accounts                    ║
║  * Security audits with explicit permission                  ║
║  * Educational purposes                                       ║
║                                                               ║
║  Prohibited uses:                                             ║
║  X Checking others' data without permission                  ║
║  X Using breach data for unauthorized access                 ║
║  X Credential stuffing or account takeover                   ║
║                                                               ║
║  DISCLAIMER: Results are intelligence, not proof.             ║
║  Comply with GDPR, CCPA, and all applicable laws.             ║
║                                                               ║
║  Use responsibly. Protect privacy. Stay legal.                ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="cyan")

    def format_password_result(self, result: Dict, show_banner: bool = True):
        """Format password check result as table

        Args:
            result: Result from PasswordChecker
            show_banner: Whether to show ethics banner
        """
        if show_banner:
            self.print_ethics_banner()

        print()

        # Check for errors
        if result.get('error'):
            self.console.print(f"[red]Error: {result['error']}[/red]")
            return

        # Create result table
        if result['compromised']:
            occurrences = result['occurrences']
            severity = result.get('severity', 'unknown')

            # Color based on severity
            if severity == 'critical':
                color = 'red bold'
                icon = '[!]'
            elif severity == 'high':
                color = 'red'
                icon = '[!]'
            elif severity == 'medium':
                color = 'yellow'
                icon = '[!]'
            else:
                color = 'yellow'
                icon = '[!]'

            table = Table(title=f"{icon} PASSWORD COMPROMISED", box=box.ROUNDED, title_style=color)
            table.add_column("Result", style="cyan")
            table.add_column("Details", style=color)

            table.add_row("Status", f"[{color}]FOUND IN BREACHES[/{color}]")
            table.add_row("Occurrences", f"{occurrences:,}")
            table.add_row("Severity", severity.upper())
            table.add_row("Hash Prefix", result.get('hash_prefix', 'N/A'))

            self.console.print(table)
            print()

            # Advice
            from net_watch.breach.password_checker import PasswordChecker
            checker = PasswordChecker()
            advice = checker.get_password_strength_advice(result)
            self.console.print(f"[bold yellow]Recommendation:[/bold yellow]")
            self.console.print(f"   {advice}")
            print()

        else:
            # Password not found
            table = Table(title="[OK] PASSWORD SAFE", box=box.ROUNDED, title_style="green")
            table.add_column("Result", style="cyan")
            table.add_column("Details", style="green")

            table.add_row("Status", "[green]NOT FOUND IN BREACHES[/green]")
            table.add_row("Hash Prefix", result.get('hash_prefix', 'N/A'))

            self.console.print(table)
            print()
            self.console.print("[green]This password was not found in known breach databases.[/green]")
            self.console.print("[dim]Note: This doesn't guarantee the password is strong - always use unique, complex passwords.[/dim]")
            print()

    def format_email_result(self, result: Dict, show_banner: bool = True):
        """Format email/domain check result as table

        Args:
            result: Result from EmailChecker
            show_banner: Whether to show ethics banner
        """
        if show_banner:
            self.print_ethics_banner()

        print()

        # Check for errors
        if result.get('error'):
            self.console.print(f"[red]Error: {result['error']}[/red]")
            return

        query_type = 'Email' if 'email' in result else 'Domain' if 'domain' in result else 'Query'
        query_value = result.get('email') or result.get('domain') or 'Unknown'

        # Summary
        total_breaches = result['total_breaches']
        confidence = result.get('confidence', 0)

        if total_breaches == 0:
            self.console.print(f"[green]No known breaches found for: {query_value}[/green]")
            self.console.print("[dim]Note: Local database checks DOMAIN-level breaches only (e.g., @yahoo.com was breached).[/dim]")
            self.console.print("[dim]      This does NOT verify if your specific email address was compromised.[/dim]")
            self.console.print("[dim]      For accurate email checking, use haveibeenpwned.com with an API key.[/dim]")
            print()
            return

        # Display breach count
        if total_breaches > 0:
            color = 'red' if total_breaches > 3 else 'yellow'
            self.console.print(f"[{color}]WARNING: {total_breaches} breach(es) found for DOMAIN: {query_value}[/{color}]")
            self.console.print(f"[dim]Note: This checks if the EMAIL DOMAIN was breached (e.g., all @yahoo.com accounts).[/dim]")
            self.console.print(f"[dim]      It does NOT confirm YOUR specific email address was in the breach.[/dim]")
            print()

        # Breach details table
        table = Table(
            title=f"Breach Details ({total_breaches} found)",
            box=box.ROUNDED
        )
        table.add_column("Breach", style="cyan", no_wrap=True)
        table.add_column("Date", style="white")
        table.add_column("Records", style="yellow", justify="right")
        table.add_column("Data Exposed", style="red")
        table.add_column("Severity", style="magenta")

        for breach in result['breaches']:
            table.add_row(
                breach['name'],
                breach['date'],
                f"{breach['records']:,}",
                ', '.join(breach['data_exposed'][:3]) + ('...' if len(breach['data_exposed']) > 3 else ''),
                breach['severity'].upper()
            )

        self.console.print(table)
        print()

        # Recommendation
        if result.get('recommendation'):
            self.console.print("[bold yellow]Recommendations:[/bold yellow]")
            self.console.print(result['recommendation'])
            print()

        # Note for username/phone
        if result.get('note'):
            self.console.print(f"[dim]Note: {result['note']}[/dim]")
            print()

    def save_to_json(self, result: Dict, query_value: str, query_type: str):
        """Save result to JSON file

        Args:
            result: Breach check result
            query_value: The value that was queried
            query_type: Type of query (email, password, domain, etc.)
        """
        # Sanitize filename
        safe_query = query_value.replace('@', '_at_').replace('.', '_').replace('/', '_')
        safe_query = ''.join(c for c in safe_query if c.isalnum() or c in ['_', '-'])

        # Create filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"breach_report_{query_type}_{safe_query}_{timestamp}.json"

        # Prepare data
        report = {
            'query': {
                'type': query_type,
                'value': query_value,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            },
            'result': result,
            'metadata': {
                'tool': 'Hound Breach Checker',
                'version': '1.0.0',
                'note': 'This report contains breach intelligence for educational/defensive purposes only.'
            }
        }

        # Save to file
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.console.print(f"[green]Report saved to: {filename}[/green]")
        return filename

    def format_as_json(self, result: Dict, query_value: str, query_type: str) -> str:
        """Format result as JSON string

        Args:
            result: Breach check result
            query_value: The value that was queried
            query_type: Type of query

        Returns:
            JSON string
        """
        report = {
            'query': {
                'type': query_type,
                'value': query_value,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            },
            'result': result
        }

        return json.dumps(report, indent=2, ensure_ascii=False)
