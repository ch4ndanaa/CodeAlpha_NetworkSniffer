import argparse
import time
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


console = Console()

packet_count = 0
protocol_counts = Counter()
start_time = None
recent_packets = []
last_payload_preview = "None"


def get_protocol_info(packet):
    """Identify protocol and extract port information."""

    if TCP in packet:
        return "TCP", packet[TCP].sport, packet[TCP].dport

    elif UDP in packet:
        return "UDP", packet[UDP].sport, packet[UDP].dport

    elif ICMP in packet:
        return "ICMP", "-", "-"

    return f"IP-{packet[IP].proto}", "-", "-"


def protocol_style(protocol):
    """Return a colour for each protocol."""

    colors = {
        "TCP": "green",
        "UDP": "cyan",
        "ICMP": "magenta"
    }

    return colors.get(protocol, "yellow")


def build_dashboard(protocol_filter):
    """Build the live network monitoring dashboard."""

    duration = time.time() - start_time if start_time else 0

    minutes = int(duration // 60)
    seconds = int(duration % 60)

    filter_text = protocol_filter if protocol_filter else "ALL"

    # Statistics panel
    stats = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=True
    )

    stats.add_column("TOTAL", justify="center")
    stats.add_column("TCP", justify="center")
    stats.add_column("UDP", justify="center")
    stats.add_column("ICMP", justify="center")
    stats.add_column("DURATION", justify="center")
    stats.add_column("FILTER", justify="center")

    stats.add_row(
        f"[bold white]{packet_count}[/bold white]",
        f"[green]{protocol_counts.get('TCP', 0)}[/green]",
        f"[cyan]{protocol_counts.get('UDP', 0)}[/cyan]",
        f"[magenta]{protocol_counts.get('ICMP', 0)}[/magenta]",
        f"[yellow]{minutes:02d}:{seconds:02d}[/yellow]",
        f"[yellow]{filter_text}[/yellow]"
    )

    stats_panel = Panel(
        stats,
        title="[bold cyan]CAPTURE STATISTICS[/bold cyan]",
        border_style="cyan"
    )

    # Packet table
    packets = Table(
        title="LIVE PACKETS",
        title_style="bold white",
        header_style="bold cyan",
        border_style="bright_black",
        expand=True
    )

    packets.add_column("#", justify="right", width=5)
    packets.add_column("TIME", width=8)
    packets.add_column("SOURCE", no_wrap=True)
    packets.add_column("DESTINATION", no_wrap=True)
    packets.add_column("PROTOCOL", justify="center", width=10)
    packets.add_column("PAYLOAD", justify="right", width=10)

    for item in recent_packets:
        number, timestamp, source, destination, protocol, payload_size = item

        color = protocol_style(protocol)

        packets.add_row(
            str(number),
            timestamp,
            source,
            destination,
            f"[{color}]{protocol}[/{color}]",
            f"{payload_size} B"
        )

    # Latest payload information
    payload_panel = Panel(
        f"[bold]Latest Payload Preview[/bold]\n"
        f"[dim]{last_payload_preview}[/dim]",
        border_style="yellow"
    )

    instructions = Panel(
        "[bold yellow]CTRL+C[/bold yellow]  Stop capture    "
        "[dim]|[/dim]    "
        "[bold green]● CAPTURING[/bold green]",
        border_style="green"
    )

    return Group(
        stats_panel,
        packets,
        payload_panel,
        instructions
    )


def analyze_packet(packet, protocol_filter, live):
    """Analyze and display a captured IPv4 packet."""

    global packet_count
    global last_payload_preview

    if IP not in packet:
        return

    protocol, source_port, destination_port = get_protocol_info(packet)

    # Apply protocol filter
    if protocol_filter and protocol != protocol_filter:
        return

    packet_count += 1
    protocol_counts[protocol] += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    source = f"{packet[IP].src}:{source_port}"
    destination = f"{packet[IP].dst}:{destination_port}"

    payload_size = 0

    if Raw in packet:
        payload = bytes(packet[Raw].load)
        payload_size = len(payload)

        # Display only the first 32 bytes
        last_payload_preview = payload[:32].hex(" ")

    else:
        last_payload_preview = "None"

    # Keep only the latest 12 packets on screen
    recent_packets.append(
        (
            packet_count,
            timestamp,
            source,
            destination,
            protocol,
            payload_size
        )
    )

    if len(recent_packets) > 12:
        recent_packets.pop(0)

    live.update(build_dashboard(protocol_filter))


def show_summary():
    """Display the final capture summary."""

    duration = time.time() - start_time if start_time else 0

    minutes = int(duration // 60)
    seconds = int(duration % 60)

    summary = Table(
        title="CAPTURE SUMMARY",
        header_style="bold cyan",
        border_style="green"
    )

    summary.add_column("Metric")
    summary.add_column("Value", justify="right")

    summary.add_row(
        "Total Packets",
        str(packet_count)
    )

    summary.add_row(
        "TCP",
        str(protocol_counts.get("TCP", 0))
    )

    summary.add_row(
        "UDP",
        str(protocol_counts.get("UDP", 0))
    )

    summary.add_row(
        "ICMP",
        str(protocol_counts.get("ICMP", 0))
    )

    summary.add_row(
        "Capture Duration",
        f"{minutes:02d}:{seconds:02d}"
    )

    console.print()
    console.print(summary)

    console.print(
        Panel(
            "[bold green]Capture stopped successfully.[/bold green]\n"
            "[dim]Thank you for using CodeAlpha Network Sniffer.[/dim]",
            border_style="green"
        )
    )


def main():
    global start_time

    parser = argparse.ArgumentParser(
        description="CodeAlpha Network Sniffer"
    )

    parser.add_argument(
        "--protocol",
        choices=["TCP", "UDP", "ICMP"],
        help="Display only the selected protocol."
    )

    args = parser.parse_args()

    console.clear()

    console.print(
        Panel(
            "[bold white]CODEALPHA NETWORK SNIFFER[/bold white]\n"
            "[bold cyan]LIVE PACKET MONITOR[/bold cyan]",
            border_style="cyan",
            padding=(1, 4)
        )
    )

    console.print(
        f"[bold]Interface:[/bold] [cyan]Wi-Fi[/cyan]    "
        f"[bold]Filter:[/bold] [yellow]{args.protocol or 'ALL'}[/yellow]"
    )

    console.print()

    start_time = time.time()

    try:
        with Live(
            build_dashboard(args.protocol),
            console=console,
            refresh_per_second=4,
            screen=False
        ) as live:

            sniff(
                iface="Wi-Fi",
                prn=lambda packet: analyze_packet(
                    packet,
                    args.protocol,
                    live
                ),
                store=False
            )

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]Capture interrupted by user.[/bold yellow]"
        )

    finally:
        show_summary()


if __name__ == "__main__":
    main()