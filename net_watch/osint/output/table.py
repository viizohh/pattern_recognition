"""Rich table output formatter for OSINT results"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from typing import Dict, Any, List


class TableFormatter:
    """Format OSINT results as Rich tables"""

    def __init__(self):
        """Initialize table formatter"""
        self.console = Console()

    def print_banner(self):
        """Print ethical use banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║  HOUND OSINT - Passive Domain Intelligence                   ║
║                                                               ║
║  WARNING: ETHICAL USE ONLY - Educational/Defensive Purposes  ║
║                                                               ║
║  This tool performs PASSIVE reconnaissance only:             ║
║  * Public DNS records, CT logs, webpages                     ║
║  * Domain-level email validation (MX/SPF/DMARC)              ║
║  X NO mailbox verification or account enumeration            ║
║  X NO credential testing or login attempts                   ║
║                                                               ║
║  Use responsibly. Respect rate limits. Obey laws.            ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="cyan")

    def print_summary(self, results: Dict[str, Any]):
        """Print complete OSINT summary

        Args:
            results: OSINT results dictionary
        """
        domain = results.get('domain', 'Unknown')

        self.console.print(f"\n[bold cyan]OSINT Results for: {domain}[/bold cyan]\n")

        # RDAP/WHOIS Information
        if 'rdap' in results and results['rdap']:
            self._print_rdap(results['rdap'])

        # DNS Information
        if 'dns' in results:
            self._print_dns(results['dns'])

        # Certificate Transparency Subdomains
        if 'ct_subdomains' in results and results['ct_subdomains']:
            self._print_ct_subdomains(results['ct_subdomains'])

        # Web Findings
        if 'web_findings' in results:
            self._print_web_findings(results['web_findings'])

        # Guessed Emails
        if 'guessed_emails' in results:
            self._print_guessed_emails(results['guessed_emails'])

        # Email Validation
        if 'email_validation' in results:
            self._print_email_validation(results['email_validation'])

        # Risk Notes
        if 'risk_notes' in results and results['risk_notes']:
            self._print_risk_notes(results['risk_notes'])

        # Errors
        if 'errors' in results and results['errors']:
            self._print_errors(results['errors'])

    def _print_rdap(self, rdap: Dict):
        """Print RDAP/WHOIS table"""
        table = Table(title="📋 Domain Registration (RDAP)", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        if rdap.get('registrar'):
            table.add_row("Registrar", rdap['registrar'])

        if rdap.get('created'):
            table.add_row("Created", rdap['created'])

        if rdap.get('updated'):
            table.add_row("Updated", rdap['updated'])

        if rdap.get('expires'):
            table.add_row("Expires", rdap['expires'])

        if rdap.get('status'):
            table.add_row("Status", ', '.join(rdap['status']))

        if rdap.get('nameservers'):
            table.add_row("Nameservers", '\n'.join(rdap['nameservers']))

        self.console.print(table)
        print()

    def _print_dns(self, dns: Dict):
        """Print DNS records table"""
        table = Table(title="DNS Records", box=box.ROUNDED)
        table.add_column("Record Type", style="cyan")
        table.add_column("Values", style="white")

        if dns.get('a_records'):
            table.add_row("A (IPv4)", '\n'.join(dns['a_records']))

        if dns.get('aaaa_records'):
            table.add_row("AAAA (IPv6)", '\n'.join(dns['aaaa_records']))

        if dns.get('ns_records'):
            table.add_row("NS (Nameservers)", '\n'.join(dns['ns_records']))

        if dns.get('mx_records'):
            mx_list = [f"{mx['host']} (priority: {mx['priority']})" for mx in dns['mx_records']]
            table.add_row("MX (Mail)", '\n'.join(mx_list))

        if dns.get('spf'):
            table.add_row("SPF", dns['spf'])

        if dns.get('dmarc'):
            table.add_row("DMARC", dns['dmarc'])

        if dns.get('txt_records') and len(dns['txt_records']) > 0:
            # Limit TXT records display (can be long)
            txt_display = dns['txt_records'][:5]
            if len(dns['txt_records']) > 5:
                txt_display.append(f"... and {len(dns['txt_records']) - 5} more")
            table.add_row("TXT Records", '\n'.join(txt_display))

        self.console.print(table)
        print()

    def _print_ct_subdomains(self, subdomains: List[str]):
        """Print Certificate Transparency subdomains"""
        table = Table(
            title=f"Certificate Transparency Subdomains ({len(subdomains)} found)",
            box=box.ROUNDED
        )
        table.add_column("Subdomain", style="cyan")

        # Show first 20, then summarize
        display_count = min(20, len(subdomains))
        for subdomain in sorted(subdomains)[:display_count]:
            table.add_row(subdomain)

        if len(subdomains) > 20:
            table.add_row(f"[dim]... and {len(subdomains) - 20} more subdomains[/dim]")

        self.console.print(table)
        print()

    def _print_web_findings(self, findings: Dict):
        """Print web scraping findings"""
        # Summary
        self.console.print(f"[bold cyan]Web Scraping Results[/bold cyan]")
        self.console.print(f"  Pages checked: {len(findings.get('pages_checked', []))}")
        self.console.print(f"  Pages successful: {len(findings.get('pages_successful', []))}\n")

        # Emails found
        if findings.get('emails'):
            table = Table(title="Email Addresses Found", box=box.ROUNDED)
            table.add_column("Email", style="green")
            for email in sorted(findings['emails']):
                table.add_row(email)
            self.console.print(table)
            print()

        # Phone numbers found
        if findings.get('phones'):
            table = Table(title="Phone Numbers Found", box=box.ROUNDED)
            table.add_column("Phone", style="yellow")
            for phone in findings['phones']:
                table.add_row(phone)
            self.console.print(table)
            print()

        # Names found
        if findings.get('names'):
            table = Table(title="Names Found", box=box.ROUNDED)
            table.add_column("Name", style="magenta")
            for name in sorted(findings['names'])[:10]:  # Limit to 10
                table.add_row(name)
            if len(findings['names']) > 10:
                table.add_row(f"[dim]... and {len(findings['names']) - 10} more[/dim]")
            self.console.print(table)
            print()

        # Organizations found
        if findings.get('organizations'):
            table = Table(title="Organizations Found", box=box.ROUNDED)
            table.add_column("Organization", style="blue")
            for org in sorted(findings['organizations'])[:10]:  # Limit to 10
                table.add_row(org)
            if len(findings['organizations']) > 10:
                table.add_row(f"[dim]... and {len(findings['organizations']) - 10} more[/dim]")
            self.console.print(table)
            print()

    def _print_guessed_emails(self, guessed: Dict):
        """Print guessed email addresses"""
        if not guessed.get('emails'):
            return

        table = Table(
            title="Guessed Email Addresses (UNVERIFIED)",
            box=box.ROUNDED
        )
        table.add_column("Email", style="yellow")
        table.add_column("Note", style="dim")

        for email in sorted(guessed['emails']):
            table.add_row(email, "Guessed from keywords")

        self.console.print(table)
        self.console.print("[yellow]WARNING: These emails are GUESSED and may not exist[/yellow]\n")

    def _print_email_validation(self, validation: Dict):
        """Print email validation results"""
        table = Table(title="Email Domain Validation", box=box.ROUNDED)
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="white")

        # MX records
        if validation.get('domain_has_mx'):
            table.add_row("MX Records", "[green]Present[/green]")
        else:
            table.add_row("MX Records", "[red]Not Found[/red]")

        # SPF
        if validation.get('spf_present'):
            table.add_row("SPF Record", "[green]Present[/green]")
        else:
            table.add_row("SPF Record", "[yellow]Not Found[/yellow]")

        # DMARC
        if validation.get('dmarc_present'):
            table.add_row("DMARC Record", "[green]Present[/green]")
        else:
            table.add_row("DMARC Record", "[yellow]Not Found[/yellow]")

        self.console.print(table)
        print()

    def _print_risk_notes(self, notes: List[str]):
        """Print security risk notes"""
        self.console.print("[bold yellow]Security Observations:[/bold yellow]")
        for note in notes:
            self.console.print(f"  * {note}")
        print()

    def _print_errors(self, errors: List):
        """Print errors encountered"""
        self.console.print("[bold red]Errors Encountered:[/bold red]")
        for error in errors:
            if isinstance(error, dict):
                self.console.print(f"  * {error}")
            else:
                self.console.print(f"  * {error}")
        print()
