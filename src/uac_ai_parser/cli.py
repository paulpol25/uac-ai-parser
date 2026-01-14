"""
CLI interface for UAC AI Parser.

Provides command-line interface for parsing, analyzing, and
querying UAC forensic outputs with AI assistance.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from uac_ai_parser.integrations.plaso import PlasoIntegration

# Setup console
console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.group()
@click.version_option(version="0.1.0", prog_name="uac-ai")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """
    UAC AI Parser - AI-powered forensic analysis for UAC outputs.
    
    Parse and analyze Unix-like Artifacts Collector (UAC) outputs
    using AI for anomaly detection and incident response.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)
    
    if not ctx.invoked_subcommand:
        # Show banner if no subcommand (or just on main)
        console.print(r"""
[bold cyan]
  _   _   _    ____      _    ___   ____arser
 | | | | / \  / ___|    / \  |_ _| |  _ \
 | | | |/ _ \| |       / _ \  | |  | |_) |
 | |_| / ___ \ |___   / ___ \ | |  |  __/
  \___/_/   \_\____| /_/   \_\___| |_|
[/bold cyan]
[dim]Unix-like Artifacts Collector AI Parser[/dim]
""")


@main.command()
@click.argument("archive", type=click.Path(exists=True))
@click.option(
    "-o", "--output",
    type=click.Path(),
    help="Output directory for extracted/parsed data",
)
@click.option(
    "--format",
    type=click.Choice(["json", "summary", "full"]),
    default="summary",
    help="Output format",
)
@click.pass_context
def parse(
    ctx: click.Context,
    archive: str,
    output: Optional[str],
    format: str,
) -> None:
    """
    Parse a UAC output archive.
    
    Extracts and parses all artifacts from a UAC tar.gz or zip file
    into structured format ready for analysis.
    """
    from uac_ai_parser.core.parser import UACParser
    
    console.print(f"\n[bold]Parsing UAC archive:[/bold] {archive}\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Extracting and parsing...", total=None)
        
        try:
            parser = UACParser(archive, extract_dir=output)
            artifacts = parser.parse()
            
            progress.update(task, description="Parse complete!")
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise click.Abort()
    
    # Display results
    if format == "summary":
        _display_parse_summary(artifacts)
    elif format == "json":
        console.print_json(data=artifacts.to_json())
    else:
        _display_parse_full(artifacts)
    
    if output:
        # Save structured data
        output_path = Path(output) / "structured_data.json"
        with open(output_path, "w") as f:
            json.dump(artifacts.structured_data, f, indent=2, default=str)
        console.print(f"\n[green]Saved structured data to:[/green] {output_path}")


def _display_parse_summary(artifacts) -> None:
    """Display parsing summary."""
    table = Table(title="UAC Parse Summary")
    table.add_column("Artifact Type", style="cyan")
    table.add_column("Count", justify="right", style="green")
    
    table.add_row("Hostname", artifacts.hostname or "Unknown")
    table.add_row("OS Type", artifacts.os_type or "Unknown")
    table.add_row("Collection Time", str(artifacts.collection_time) if artifacts.collection_time else "Unknown")
    table.add_row("", "")
    
    if artifacts.bodyfile:
        table.add_row("Bodyfile Entries", str(artifacts.bodyfile.total_entries))
        table.add_row("  - Executables", str(len(artifacts.bodyfile.executables)))
        table.add_row("  - SUID/SGID Files", str(len(artifacts.bodyfile.setuid_files)))
    
    if artifacts.live_response:
        table.add_row("Processes", str(len(artifacts.live_response.processes)))
        table.add_row("Network Connections", str(len(artifacts.live_response.network_connections)))
        table.add_row("Users", str(len(artifacts.live_response.users)))
    
    table.add_row("Hash Entries", str(len(artifacts.hash_data)))
    table.add_row("Log Entries", str(len(artifacts.logs)))
    table.add_row("Timeline Events", str(len(artifacts.timeline)))
    
    console.print(table)


def _display_parse_full(artifacts) -> None:
    """Display full parsing results."""
    _display_parse_summary(artifacts)
    
    # Show sample processes
    if artifacts.live_response and artifacts.live_response.processes:
        console.print("\n[bold]Sample Processes:[/bold]")
        proc_table = Table()
        proc_table.add_column("PID")
        proc_table.add_column("User")
        proc_table.add_column("Command")
        
        for proc in artifacts.live_response.processes[:10]:
            proc_table.add_row(
                str(proc.pid),
                proc.user or "-",
                (proc.command or "")[:60],
            )
        
        console.print(proc_table)
    
    # Show network connections
    if artifacts.live_response and artifacts.live_response.network_connections:
        console.print("\n[bold]Sample Network Connections:[/bold]")
        net_table = Table()
        net_table.add_column("Protocol")
        net_table.add_column("Local")
        net_table.add_column("Remote")
        net_table.add_column("State")
        net_table.add_column("Process")
        
        for conn in artifacts.live_response.network_connections[:10]:
            net_table.add_row(
                conn.protocol,
                f"{conn.local_address}:{conn.local_port}",
                f"{conn.remote_address}:{conn.remote_port}" if conn.remote_address else "-",
                conn.state or "-",
                conn.program or "-",
            )
        
        console.print(net_table)


@main.command()
@click.argument("archive", type=click.Path(exists=True))
@click.option(
    "-q", "--query",
    help="Analysis query (e.g., 'lateral movement indicators')",
)
@click.option(
    "--anomalies",
    is_flag=True,
    help="Run anomaly detection",
)
@click.option(
    "--model",
    default="llama3.1",
    help="LLM model to use",
)
@click.option(
    "--provider",
    type=click.Choice(["ollama", "openai"]),
    default="ollama",
    help="LLM provider",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    help="Save report to file",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    archive: str,
    query: Optional[str],
    anomalies: bool,
    model: str,
    provider: str,
    output: Optional[str],
) -> None:
    """
    AI-powered analysis of UAC output.
    
    Use natural language queries or run anomaly detection
    on forensic artifacts.
    """
    from uac_ai_parser.core.parser import UACParser
    from uac_ai_parser.ai.analyzer import AIAnalyzer
    
    if not query and not anomalies:
        console.print("[yellow]Please specify --query or --anomalies[/yellow]")
        raise click.Abort()
    
    console.print(f"\n[bold]Analyzing:[/bold] {archive}")
    console.print(f"[bold]Model:[/bold] {model} ({provider})\n")
    
    # Parse first
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing artifacts...", total=None)
        
        parser = UACParser(archive)
        artifacts = parser.parse()
        
        progress.update(task, description="Initializing AI analyzer...")
        
        try:
            analyzer = AIAnalyzer(model=model, provider=provider)
            
            # Pre-calculate chunks to set progress total
            # We'll just define a callback that creates a sub-progress for embeddings
            def embedding_progress_callback(n):
                progress.update(task, advance=0, description=f"Embedding chunks... ({n} processed)")

            analyzer.load_artifacts(artifacts, progress_callback=embedding_progress_callback)
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            console.print("\n[yellow]Make sure Ollama is running: ollama serve[/yellow]")
            raise click.Abort()
        
        progress.update(task, description="Running analysis...")
        
        if anomalies:
            report = analyzer.detect_anomalies()
            progress.update(task, description="Analysis complete!")
            
            # Display report
            console.print("\n")
            console.print(Markdown(report.to_markdown()))
            
            if output:
                with open(output, "w") as f:
                    f.write(report.to_markdown())
                console.print(f"\n[green]Report saved to:[/green] {output}")
        
        if query:
            result = analyzer.query(query)
            progress.update(task, description="Query complete!")
            
            # Display result
            console.print("\n")
            console.print(Panel(
                f"[bold]Query:[/bold] {query}",
                title="Analysis Query",
            ))
            console.print(Markdown(result.answer))
            
            if result.evidence:
                console.print("\n[bold]Supporting Evidence:[/bold]")
                for ev in result.evidence[:5]:
                    console.print(f"  • {ev.artifact_type}: {ev.raw_data[:100] if ev.raw_data else 'N/A'}...")
            
            if result.suggested_queries:
                console.print("\n[bold]Suggested Follow-up Queries:[/bold]")
                for sq in result.suggested_queries:
                    console.print(f"  • {sq}")


@main.command()
@click.argument("archive", type=click.Path(exists=True))
@click.option(
    "--model",
    default="llama3.1",
    help="LLM model to use",
)
@click.option(
    "--provider",
    type=click.Choice(["ollama", "openai"]),
    default="ollama",
    help="LLM provider",
)
@click.pass_context
def interactive(
    ctx: click.Context,
    archive: str,
    model: str,
    provider: str,
) -> None:
    """
    Start interactive analysis session.
    
    Load UAC artifacts and query them interactively
    using natural language.
    """
    from uac_ai_parser.core.parser import UACParser
    from uac_ai_parser.ai.analyzer import AIAnalyzer
    
    console.print(f"\n[bold]Loading:[/bold] {archive}")
    console.print(f"[bold]Model:[/bold] {model} ({provider})\n")
    
    # Parse and initialize
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading artifacts...", total=None)
        
        parser = UACParser(archive)
        artifacts = parser.parse()
        
        progress.update(task, description="Initializing AI...")
        
        try:
            analyzer = AIAnalyzer(model=model, provider=provider)
            
            def embedding_progress_callback(n):
                progress.update(task, advance=0, description=f"Embedding chunks... ({n} processed)")
                
            analyzer.load_artifacts(artifacts, progress_callback=embedding_progress_callback)
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise click.Abort()
    
    # Display summary
    _display_parse_summary(artifacts)
    
    console.print("\n[bold green]Interactive session started![/bold green]")
    console.print("Type your questions, or use commands:")
    console.print("  [cyan]/anomalies[/cyan] - Run anomaly detection")
    console.print("  [cyan]/summary[/cyan]   - Generate incident summary")
    console.print("  [cyan]/save[/cyan]      - Save last result to file")
    console.print("  [cyan]/help[/cyan]      - Show help")
    console.print("  [cyan]/quit[/cyan]      - Exit\n")
    
    last_result = None
    
    while True:
        try:
            query = Prompt.ask("[bold cyan]>[/bold cyan]")
            
            if not query.strip():
                continue
            
            if query.lower() in ("/quit", "/exit", "/q"):
                console.print("[yellow]Goodbye![/yellow]")
                break
            
            if query.lower() == "/help":
                console.print("\n[bold]Available Commands:[/bold]")
                console.print("  /anomalies - Run anomaly detection")
                console.print("  /summary   - Generate incident summary")
                console.print("  /save      - Save last analysis result")
                console.print("  /quit      - Exit interactive mode")
                console.print("\n[bold]Example Queries:[/bold]")
                console.print("  What SSH activity occurred?")
                console.print("  Show suspicious processes")
                console.print("  Are there signs of lateral movement?")
                console.print("  What persistence mechanisms exist?\n")
                continue
            
            if query.lower().startswith("/anomalies"):
                with console.status("Running anomaly detection..."):
                    report = analyzer.detect_anomalies()
                console.print(Markdown(report.to_markdown()))
                
                # Auto-save results
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                md_file = f"anomalies_{ts}.md"
                csv_file = f"anomalies_{ts}.csv"
                
                # Save Markdown
                with open(md_file, "w") as f:
                    f.write(report.to_markdown())
                
                # Save CSV
                try:
                    import pandas as pd
                    # Flatten anomalies for CSV
                    data = []
                    for a in report.anomalies:
                        row = {
                            "id": a.anomaly_id,
                            "type": a.anomaly_type,
                            "severity": a.severity,
                            "score": a.score,
                            "title": a.title,
                            "description": a.description,
                            "artifact": a.source_artifact
                        }
                        data.append(row)
                    pd.DataFrame(data).to_csv(csv_file, index=False)
                    console.print(f"\n[green]Results saved to {md_file} and {csv_file}[/green]")
                except ImportError:
                    console.print(f"\n[green]Report saved to {md_file}[/green] (Install pandas for CSV support)")
                continue
            
            if query.lower().startswith("/summary"):
                with console.status("Generating summary..."):
                    summary = analyzer.generate_summary()
                console.print(Markdown(summary.to_markdown()))
                
                # Auto-save results
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                md_file = f"summary_{ts}.md"
                with open(md_file, "w") as f:
                    f.write(summary.to_markdown())
                console.print(f"\n[green]Summary saved to {md_file}[/green]")
                continue
            
            if query.lower().startswith("/save"):
                if last_result:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    fname = f"analysis_{ts}.md"
                    with open(fname, "w") as f:
                        f.write(f"# Analysis Query: {last_result.query}\n\n")
                        f.write(last_result.answer)
                        if last_result.evidence:
                            f.write("\n\n## Evidence\n")
                            for ev in last_result.evidence:
                                f.write(f"- {ev.artifact_type}: {ev.raw_data}\n")
                    console.print(f"[green]Last result saved to {fname}[/green]")
                else:
                    console.print("[yellow]No result to save yet[/yellow]")
                continue
            
            # Regular query
            console.print()
            with console.status("Analyzing..."):
                result = analyzer.query(query)
                last_result = result
            
            console.print(Markdown(result.answer))
            
            if result.suggested_queries:
                console.print("\n[dim]Suggested queries:[/dim]")
                for sq in result.suggested_queries:
                    console.print(f"  [dim]• {sq}[/dim]")
            console.print()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Use /quit to exit[/yellow]")
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")


@main.command()
@click.argument("archive", type=click.Path(exists=True))
@click.option(
    "--format",
    type=click.Choice(["jsonl", "json", "csv", "markdown"]),
    default="jsonl",
    help="Export format",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    required=True,
    help="Output file path",
)
@click.option(
    "--include-timeline/--no-timeline",
    default=True,
    help="Include timeline data",
)
@click.pass_context
def export(
    ctx: click.Context,
    archive: str,
    format: str,
    output: str,
    include_timeline: bool,
) -> None:
    """
    Export parsed UAC data.
    
    Export to various formats including JSONL (for Timesketch),
    JSON, CSV, or Markdown reports.
    """
    from uac_ai_parser.core.parser import UACParser
    from uac_ai_parser.core.preprocessor import Preprocessor
    
    console.print(f"\n[bold]Exporting:[/bold] {archive}")
    console.print(f"[bold]Format:[/bold] {format}")
    console.print(f"[bold]Output:[/bold] {output}\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing...", total=None)
        
        parser = UACParser(archive, generate_timeline=include_timeline)
        artifacts = parser.parse()
        
        progress.update(task, description="Exporting...")
        
        output_path = Path(output)
        
        if format == "jsonl":
            # Export timeline for Timesketch
            with open(output_path, "w") as f:
                for event in artifacts.timeline:
                    f.write(json.dumps(event.to_timesketch_format(), default=str) + "\n")
            count = len(artifacts.timeline)
            
        elif format == "json":
            # Export structured data
            with open(output_path, "w") as f:
                json.dump(artifacts.structured_data, f, indent=2, default=str)
            count = len(artifacts.structured_data)
            
        elif format == "csv":
            # Export bodyfile as CSV
            if artifacts.bodyfile:
                df = artifacts.bodyfile.to_dataframe()
                df.to_csv(output_path, index=False)
                count = len(df)
            else:
                console.print("[yellow]No bodyfile data to export[/yellow]")
                return
                
        elif format == "markdown":
            # Export as markdown report
            preprocessor = Preprocessor()
            chunks = preprocessor.process(artifacts)
            
            with open(output_path, "w") as f:
                f.write(f"# UAC Analysis Report\n\n")
                f.write(f"**Source:** {archive}\n")
                f.write(f"**Hostname:** {artifacts.hostname}\n")
                f.write(f"**Collection Time:** {artifacts.collection_time}\n\n")
                
                for chunk in chunks[:50]:  # Limit for readability
                    f.write(f"\n{chunk.content}\n")
            
            count = len(chunks)
        
        progress.update(task, description="Export complete!")
    
    console.print(f"[green]Exported {count} items to {output}[/green]")


@main.command()
@click.argument("archive", type=click.Path(exists=True))
@click.option(
    "-o", "--output",
    type=click.Path(),
    default="timeline.html",
    help="Output HTML file (or directory for Plaso outputs)",
)
@click.option(
    "--start",
    help="Start time filter (ISO format)",
)
@click.option(
    "--end",
    help="End time filter (ISO format)",
)
@click.option(
    "--use-plaso",
    is_flag=True,
    help="Use Plaso for super timeline generation (requires Docker)",
)
@click.option(
    "--plaso-image",
    default="log2timeline/plaso:latest",
    help="Plaso Docker image to use",
)
@click.pass_context
def timeline(
    ctx: click.Context,
    archive: str,
    output: str,
    start: Optional[str],
    end: Optional[str],
    use_plaso: bool,
    plaso_image: str,
) -> None:
    """
    Generate timeline visualization.
    
    Creates an interactive HTML timeline of forensic events using Plotly. 
    
    If --use-plaso is specified, it runs a Dockerized Plaso instance to generate 
    a comprehensive bodyfile/event list, which is then parsed and visualized.
    This provides significantly more detail than the default parser.
    """
    from datetime import datetime
    from uac_ai_parser.core.parser import UACParser
    
    console.print(f"\n[bold]Generating timeline:[/bold] {archive}\n")
    
    # Plaso Integration
    plaso_events = []
    if use_plaso:
        plaso = PlasoIntegration(docker_image=plaso_image)
        if not plaso.is_available():
            console.print("[yellow]Plaso/Docker not available. Falling back to internal parser.[/yellow]")
        else:
            with console.status("Running Plaso (this may take a while)..."):
                # Use archive directory for output if not specified or if output is a file
                output_path_obj = Path(output)
                output_dir = output_path_obj.parent if output_path_obj.suffix else output_path_obj
                
                timeline_csv = plaso.generate_timeline(archive, output_dir)
                
                if timeline_csv and timeline_csv.exists():
                    console.print(f"[green]Plaso timeline generated:[/green] {timeline_csv}")
                    
                    # Parse Plaso CSV for visualization
                    console.print("Parsing Plaso CSV for visualization...")
                    raw_events = plaso.parse_l2tcsv(timeline_csv)
                    
                    # Normalize Plaso events to match our internal format
                    for e in raw_events:
                        if not e.get("timestamp"):
                            continue
                        
                        plaso_events.append({
                            "timestamp": e["timestamp"],
                            "source_type": e.get("sourcetype", "plaso"),
                            "source": e.get("source", "plaso"),
                            "message": f"{e.get('desc', '')} ({e.get('filename', '')})",
                        })
                    
                    console.print(f"Loaded {len(plaso_events)} events from Plaso timeline")
                else:
                    console.print("[red]Plaso generation failed. Falling back to internal parser.[/red]")

    # Internal Parser (if Plaso not used or failed, OR if we want to combine? For now, exclusive or fall-through)
    internal_events = []
    hostname = "Unknown"
    
    if not plaso_events:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Parsing artifacts...", total=None)
            
            parser = UACParser(archive)
            artifacts = parser.parse()
            hostname = artifacts.hostname or "Unknown"
            
            progress.update(task, description="Building timeline...")
            
            for e in artifacts.timeline:
                internal_events.append({
                    "timestamp": e.timestamp,
                    "source_type": e.source_type,
                    "source": e.source,
                    "message": e.message,
                })

    # Combine events (prioritize Plaso if available, otherwise internal)
    # If Plaso was successful, plaso_events is populated.
    events_data = plaso_events if plaso_events else internal_events
    
    # Filter by time range if specified
    if start:
        start_dt = datetime.fromisoformat(start)
        events_data = [e for e in events_data if e["timestamp"] >= start_dt]
    if end:
        end_dt = datetime.fromisoformat(end)
        events_data = [e for e in events_data if e["timestamp"] <= end_dt]
    
    if not events_data:
        console.print("[yellow]No timeline events found[/yellow]")
        return
    
    console.print("Generating visualization...")
    
    try:
        import plotly.express as px
        import pandas as pd
        
        # Convert to DataFrame
        # Limit to reasonable number for visualization to avoid browser crash
        limit = 20000
        if len(events_data) > limit:
            console.print(f"[yellow]Warning: Limiting visualization to first {limit} events (out of {len(events_data)})[/yellow]")
        
        df = pd.DataFrame([
            {
                "timestamp": e["timestamp"],
                "source_type": e["source_type"],
                "source": e["source"],
                "message": e["message"][:200],  # Truncate long messages
            }
            for e in events_data[:limit]
        ])
        
        # Create figure
        fig = px.scatter(
            df,
            x="timestamp",
            y="source_type",
            color="source_type",
            hover_data=["source", "message"],
            title=f"Timeline: {hostname} ({len(df)} events)",
        )
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Event Type",
            height=800,
        )
        
        # Ensure output is a file path
        output_file = Path(output)
        if output_file.is_dir():
            output_file = output_file / "timeline.html"
            
        fig.write_html(str(output_file))
        console.print(f"[green]Visualization saved to:[/green] {output_file}")
            
    except ImportError:
        console.print("[red]Plotly required for visualization. Install with:[/red]")
        console.print("pip install plotly")
        raise click.Abort()
    
    console.print(f"[green]Timeline saved to:[/green] {output}")
    console.print(f"Total events: {len(events_data)}")


@main.command()
@click.pass_context
def check(ctx: click.Context) -> None:
    """
    Check system requirements.
    
    Verify that all required dependencies and services
    are available.
    """
    console.print("\n[bold]Checking UAC AI Parser requirements...[/bold]\n")
    
    checks = []
    
    # Check Python version
    import sys
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python >= 3.10", py_version, py_ok))
    
    # Check required packages
    packages = [
        ("pandas", "pandas"),
        ("rich", "rich"),
        ("click", "click"),
        ("pydantic", "pydantic"),
        ("httpx", "httpx"),
    ]
    
    for name, module in packages:
        try:
            __import__(module)
            checks.append((name, "✓ installed", True))
        except ImportError:
            checks.append((name, "✗ not installed", False))
    
    # Check optional packages
    optional = [
        ("chromadb", "chromadb", "Vector store"),
        ("sentence_transformers", "sentence_transformers", "Embeddings"),
        ("plotly", "plotly", "Visualizations"),
    ]
    
    for name, module, desc in optional:
        try:
            __import__(module)
            checks.append((f"{name} ({desc})", "✓ installed", True))
        except ImportError:
            checks.append((f"{name} ({desc})", "✗ optional", None))
    
    # Check Ollama
    try:
        import httpx
        response = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            model_names = [m["name"] for m in models[:3]]
            checks.append(("Ollama", f"✓ running ({len(models)} models)", True))
        else:
            checks.append(("Ollama", "✗ error", False))
    except Exception:
        checks.append(("Ollama", "✗ not running", False))
    except Exception:
        checks.append(("Ollama", "✗ not running", False))
        
    # Check Docker (for Plaso)
    try:
        import subprocess
        docker_res = subprocess.run(["docker", "--version"], capture_output=True, timeout=2)
        if docker_res.returncode == 0:
            checks.append(("Docker", "✓ installed", True))
        else:
            checks.append(("Docker", "✗ error", False))
    except FileNotFoundError:
        checks.append(("Docker", "✗ not installed", False))
    except Exception:
        checks.append(("Docker", "✗ error", False))
    
    # Display results
    table = Table(title="System Check")
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("", width=3)
    
    all_ok = True
    for name, status, ok in checks:
        if ok is True:
            icon = "✅"
        elif ok is False:
            icon = "❌"
            all_ok = False
        else:
            icon = "⚠️"
        
        table.add_row(name, status, icon)
    
    console.print(table)
    
    if all_ok:
        console.print("\n[green]All checks passed![/green]")
    else:
        console.print("\n[yellow]Some requirements are missing.[/yellow]")
        console.print("Run: pip install uac-ai-parser[dev]")
        console.print("And ensure Ollama is running: ollama serve")


if __name__ == "__main__":
    main()
