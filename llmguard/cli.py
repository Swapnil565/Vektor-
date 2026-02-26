"""
LLMGuard-Lite CLI interface.

Commands:
    llmguard            - Interactive wizard (default)
    llmguard scan       - Run security scan against an LLM target
    llmguard demo       - Show demo results (no API key needed)
    llmguard list       - List all available attacks
    llmguard info       - Show details about a specific attack
"""
import sys
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich import box

from llmguard import __version__


console = Console()

PROVIDERS = ["openai", "groq", "openrouter", "together", "ollama", "gemini", "multi-agent", "vulnerable"]

PROVIDER_DESCRIPTIONS = {
    "openai":       "OpenAI  (GPT-4o, GPT-3.5, ...)",
    "groq":         "Groq    (Llama 3, Mixtral, fast inference)",
    "openrouter":   "OpenRouter  (100+ models, free tier available)",
    "together":     "Together AI  (open-source models)",
    "ollama":       "Ollama  (local models, no key needed)",
    "gemini":       "Google Gemini  (free tier: 500 req/day)",
    "multi-agent":  "Multi-Agent  (3-hop Gemini pipeline)",
    "vulnerable":   "Vulnerable  (intentionally broken target, no key)",
}

LOGO = """\
  ██╗     ██╗     ███╗   ███╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║     ██║     ████╗ ████║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║     ██╔████╔██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║     ██║     ██║╚██╔╝██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ███████╗███████╗██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"""


def _print_logo():
    console.print(f"[bold cyan]{LOGO}[/bold cyan]")
    console.print(
        f"  [dim]Security Scanner for LLM Applications[/dim]"
        f"  [bold]v{__version__}[/bold]\n"
    )


def _pick_provider() -> str:
    """Numbered provider picker."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("num",  style="bold cyan",  no_wrap=True)
    table.add_column("name", style="bold white", no_wrap=True)
    table.add_column("desc", style="dim")

    no_key = {"ollama", "vulnerable"}
    for i, p in enumerate(PROVIDERS, 1):
        note = "  [dim](no key needed)[/dim]" if p in no_key else ""
        table.add_row(f"[{i}]", p, PROVIDER_DESCRIPTIONS[p] + note)

    console.print(table)

    while True:
        raw = Prompt.ask(
            "[bold cyan]>[/bold cyan] Select provider",
            default="6"
        ).strip()
        if raw.isdigit() and 1 <= int(raw) <= len(PROVIDERS):
            return PROVIDERS[int(raw) - 1]
        if raw in PROVIDERS:
            return raw
        console.print(f"[red]Enter a number 1-{len(PROVIDERS)} or a provider name.[/red]")


def _get_api_key(provider: str) -> Optional[str]:
    """Prompt for API key; skip for providers that don't need one."""
    no_key = {"ollama", "vulnerable"}
    if provider in no_key:
        return None

    # Try env first
    from llmguard.config import Config
    try:
        key = Config.get_api_key(provider, required=False)
        if key:
            masked = key[:8] + "..." + key[-4:]
            console.print(f"  [dim]Using key from environment: {masked}[/dim]")
            return key
    except Exception:
        pass

    key = Prompt.ask(
        f"[bold cyan]>[/bold cyan] Enter your [bold]{provider.upper()}[/bold] API key",
        password=True
    ).strip()
    return key or None


def _run_wizard():
    """Full interactive wizard — triggered when llmguard is run with no subcommand."""
    _print_logo()

    # ── STEP 1: provider ────────────────────────────────────────────────────
    console.rule("[bold cyan]Step 1 — Choose a provider[/bold cyan]", style="cyan")
    console.print()
    provider = _pick_provider()
    console.print()

    # ── STEP 2: API key ─────────────────────────────────────────────────────
    console.rule("[bold cyan]Step 2 — API key[/bold cyan]", style="cyan")
    console.print()
    api_key = _get_api_key(provider)
    console.print()

    # ── STEP 3: system prompt ───────────────────────────────────────────────
    console.rule("[bold cyan]Step 3 — System prompt  [dim](optional)[/dim][/bold cyan]", style="cyan")
    console.print(
        "  Paste the system prompt of the application you're testing.\n"
        "  [dim]Press Enter to skip.[/dim]\n"
    )
    system_prompt = Prompt.ask(
        "[bold cyan]>[/bold cyan] System prompt",
        default=""
    ).strip() or None
    console.print()

    # ── STEP 4: quick or full ───────────────────────────────────────────────
    console.rule("[bold cyan]Step 4 — Scan depth[/bold cyan]", style="cyan")
    console.print()
    quick = Confirm.ask(
        "[bold cyan]>[/bold cyan] Quick scan? [dim](5 high-impact attacks only)[/dim]",
        default=False
    )
    console.print()

    # ── confirm ─────────────────────────────────────────────────────────────
    console.print(Panel(
        f"[cyan]Provider:[/cyan]      {provider}\n"
        f"[cyan]API key:[/cyan]       {'(set)' if api_key else '(none)'}\n"
        f"[cyan]System prompt:[/cyan] {'(set)' if system_prompt else '(none)'}\n"
        f"[cyan]Mode:[/cyan]          {'Quick (5 attacks)' if quick else 'Full (15 attacks)'}",
        title="[bold]Ready to scan[/bold]",
        border_style="cyan",
    ))
    console.print()

    if not Confirm.ask("[bold cyan]>[/bold cyan] Run scan now?", default=True):
        console.print("[dim]Aborted.[/dim]")
        sys.exit(0)

    console.print()

    # ── run scan ─────────────────────────────────────────────────────────────
    _execute_scan(
        target=provider,
        model=None,
        system_prompt=system_prompt,
        budget=1.0,
        output="report.json",
        ci=False,
        quick=quick,
        attacks=None,
        api_key=api_key,
    )


def _execute_scan(target, model, system_prompt, budget, output, ci, quick, attacks, api_key):
    """Shared scan logic used by both wizard and `scan` subcommand."""
    from llmguard.config import Config
    from llmguard.targets.factory import create_target
    from llmguard.scanner import LLMGuardScanner
    from llmguard.scoring.reporter import Reporter

    if not api_key and target not in ("ollama", "vulnerable"):
        api_key = Config.get_api_key(target)

    if not ci:
        model_label = model or "(provider default)"
        console.print(Panel(
            f"[bold cyan]LLMGuard Security Scanner v{__version__}[/bold cyan]\n"
            f"Target: {target}/{model_label}  |  Budget: ${budget:.2f}",
            border_style="cyan"
        ))

    target_kwargs = {}
    if api_key:
        target_kwargs["api_key"] = api_key
    if model:
        target_kwargs["model"] = model
    if system_prompt:
        target_kwargs["system_prompt"] = system_prompt

    try:
        llm_target = create_target(target, **target_kwargs)
    except Exception as e:
        console.print(f"[red]Error creating target: {e}[/red]")
        sys.exit(1)

    attack_list = attacks.split(",") if attacks else None
    scanner = LLMGuardScanner(llm_target, budget_limit=budget)

    total = 5 if quick else 15
    if not ci:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=total)
            results = scanner.scan(attacks=attack_list, quick_mode=quick)
            progress.update(task, completed=len(results.get("all_results", [])))
    else:
        results = scanner.scan(attacks=attack_list, quick_mode=quick)

    reporter = Reporter()

    if ci:
        import json
        click.echo(json.dumps(results, indent=2))
    else:
        reporter.print_terminal(results, console)

    reporter.save_json(results, output)
    html_path = output.replace(".json", ".html")
    reporter.save_html(results, html_path)

    if not ci:
        console.print(f"\n[green]Reports saved:[/green] {output}, {html_path}")

    risk = results.get("summary", {}).get("risk_score", 0)
    if risk >= 80:
        sys.exit(2)
    elif risk > 0:
        sys.exit(1)
    sys.exit(0)


# ── CLI group ────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="llmguard")
@click.pass_context
def cli(ctx):
    """LLMGuard-Lite: Security scanner for LLM applications."""
    if ctx.invoked_subcommand is None:
        _run_wizard()


@cli.command()
@click.option("--target", type=click.Choice(PROVIDERS), required=True, help="LLM provider to scan")
@click.option("--model", default=None, help="Model name (uses provider default if omitted)")
@click.option("--system-prompt", default=None, help="System prompt string")
@click.option("--system-prompt-file", default=None, type=click.Path(exists=True), help="Path to system prompt file")
@click.option("--budget", default=1.0, type=float, help="Max budget in USD (default: 1.0)")
@click.option("--output", default="report.json", help="Output file path (default: report.json)")
@click.option("--ci", is_flag=True, help="CI mode: JSON to stdout, no colors, no progress bar")
@click.option("--quick", is_flag=True, help="Quick mode: only run high-success-rate attacks")
@click.option("--attacks", default=None, help="Comma-separated list of attack IDs to run")
@click.option("--api-key", default=None, help="API key (or set env var: OPENAI_API_KEY, GROQ_API_KEY, etc.)")
def scan(target, model, system_prompt, system_prompt_file, budget, output, ci, quick, attacks, api_key):
    """Run a security scan against an LLM target."""
    if system_prompt_file:
        with open(system_prompt_file, "r", encoding="utf-8") as f:
            system_prompt = f.read().strip()

    _execute_scan(
        target=target,
        model=model,
        system_prompt=system_prompt,
        budget=budget,
        output=output,
        ci=ci,
        quick=quick,
        attacks=attacks,
        api_key=api_key,
    )


@cli.command()
def demo():
    """Run demo mode - no API key needed. Shows sample scan results."""
    from llmguard.demo import run_demo
    run_demo(console)


@cli.command("list")
def list_attacks():
    """List all available attacks grouped by category."""
    from llmguard.attacks.registry import ATTACK_REGISTRY, get_categories

    table = Table(title="LLMGuard Attacks", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Category", style="magenta")
    table.add_column("Expected Rate", justify="right")

    for category in sorted(get_categories()):
        for attack_id, config in ATTACK_REGISTRY.items():
            if config["category"] == category:
                rate = f"{config['expected_success_rate']:.0%}"
                table.add_row(attack_id, config["name"], config["category"], rate)

    console.print(table)
    console.print(f"\n[dim]Total: {len(ATTACK_REGISTRY)} attacks[/dim]")


@cli.command()
@click.argument("attack_id")
def info(attack_id):
    """Show details about a specific attack."""
    from llmguard.attacks.registry import ATTACK_REGISTRY

    if attack_id not in ATTACK_REGISTRY:
        console.print(f"[red]Unknown attack: {attack_id}[/red]")
        console.print("[dim]Run 'llmguard list' to see available attacks.[/dim]")
        sys.exit(1)

    attack = ATTACK_REGISTRY[attack_id]

    console.print(Panel(
        f"[bold]{attack['name']}[/bold]\n\n"
        f"[cyan]ID:[/cyan] {attack_id}\n"
        f"[cyan]Category:[/cyan] {attack['category']}\n"
        f"[cyan]Test Cases:[/cyan] {attack['test_cases']}\n"
        f"[cyan]Expected Success Rate:[/cyan] {attack['expected_success_rate']:.0%}\n\n"
        f"[cyan]Description:[/cyan]\n{attack['description']}",
        title=f"Attack: {attack_id}",
        border_style="cyan"
    ))


if __name__ == "__main__":
    cli()
