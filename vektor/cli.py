"""
Vektor CLI — AI Security Testing Framework.

Commands:
    vektor            - Interactive wizard (default)
    vektor scan       - Run security scan against an LLM target
    vektor demo       - Show demo results (no API key needed)
    vektor list       - List all available attacks
    vektor info       - Show details about a specific attack
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

from vektor import __version__


console = Console()

PROVIDERS = [
    "openai", "groq", "openrouter", "together", "ollama", "gemini", "multi-agent",
    # Open-source local LLM apps
    "lmstudio", "localai", "openwebui", "anythingllm", "jan",
    "vulnerable",
    # Generic HTTP endpoint (use with --url)
    "http",
]

PROVIDER_DESCRIPTIONS = {
    "openai":       "OpenAI  (GPT-4o, GPT-3.5, ...)",
    "groq":         "Groq    (Llama 3, Mixtral, fast inference)",
    "openrouter":   "OpenRouter  (100+ models, free tier available)",
    "together":     "Together AI  (open-source models)",
    "ollama":       "Ollama  (local models, no key needed)",
    "gemini":       "Google Gemini  (free tier: 500 req/day)",
    "multi-agent":  "Multi-Agent  (3-hop Gemini pipeline)",
    # Local open-source apps
    "lmstudio":     "LM Studio  (localhost:1234, enable Local Server in app)",
    "localai":      "LocalAI  (localhost:8080, Docker: ghcr.io/mudler/local-ai)",
    "openwebui":    "Open WebUI  (localhost:3000, runs on top of Ollama)",
    "anythingllm":  "AnythingLLM  (localhost:3001, all-in-one RAG + chat)",
    "jan":          "Jan  (localhost:1337, desktop Electron app)",
    "vulnerable":   "Vulnerable  (intentionally broken target, no key)",
    "http":         "HTTP Endpoint  (any REST AI API, use with --url)",
}

LOGO = """\
  ██╗   ██╗███████╗██╗  ██╗████████╗ ██████╗ ██████╗ 
  ██║   ██║██╔════╝██║ ██╔╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██║   ██║█████╗  █████╔╝    ██║   ██║   ██║██████╔╝
  ╚██╗ ██╔╝██╔══╝  ██╔═██╗    ██║   ██║   ██║██╔══██╗
   ╚████╔╝ ███████╗██║  ██╗   ██║   ╚██████╔╝██║  ██║
    ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"""


def _print_logo():
    console.print(f"[bold cyan]{LOGO}[/bold cyan]")
    console.print(
        f"  [dim]AI Security Testing Framework[/dim]"
        f"  [bold]v{__version__}[/bold]\n"
    )


def _pick_provider() -> str:
    """Numbered provider picker."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("num",  style="bold cyan",  no_wrap=True)
    table.add_column("name", style="bold white", no_wrap=True)
    table.add_column("desc", style="dim")

    no_key = {"ollama", "vulnerable", "lmstudio", "localai", "jan"}
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
    no_key = {"ollama", "vulnerable", "lmstudio", "localai", "jan"}
    if provider in no_key:
        return None

    # Try env first
    from vektor.config import Config
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
    """Full interactive wizard — triggered when vektor is run with no subcommand."""
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


def _execute_scan(
    target, model, system_prompt, budget, output, ci, quick, attacks, api_key,
    base_url=None, url=None, headers=None, param_field=None, request_field="message",
    response_field="message", request_delay=0.0, plugins=(), mode="standard",
):
    """Shared scan logic used by both wizard and `scan` subcommand."""
    from vektor.config import Config
    from vektor.targets.factory import create_target
    from vektor.core.engine import VektorScanner
    from vektor.scoring.reporter import Reporter

    # HTTP target: derive from --url when target not explicitly set
    if url and target in (None, "http"):
        target = "http"

    _no_key = {"ollama", "vulnerable", "lmstudio", "localai", "jan", "http"}
    if not api_key and target not in _no_key:
        api_key = Config.get_api_key(target)

    if not ci:
        label = url or f"{target}/{model or '(default)'}"
        console.print(Panel(
            f"[bold cyan]Vektor Security Scanner v{__version__}[/bold cyan]\n"
            f"Target: {label}  |  Budget: ${budget:.2f}  |  Mode: {mode}",
            border_style="cyan"
        ))

    target_kwargs = {}
    if api_key:
        target_kwargs["api_key"] = api_key
    if model:
        target_kwargs["model"] = model
    if system_prompt:
        target_kwargs["system_prompt"] = system_prompt
    if base_url:
        target_kwargs["base_url"] = base_url
    # HTTP-specific kwargs
    if target == "http":
        if not url:
            console.print("[red]--url is required when using --target http[/red]")
            sys.exit(1)
        target_kwargs["url"] = url
        if headers:
            parsed_headers = {}
            for h in headers:
                if ":" in h:
                    k, _, v = h.partition(":")
                    parsed_headers[k.strip()] = v.strip()
            target_kwargs["headers"] = parsed_headers
        if request_field != "message":
            target_kwargs["request_field"] = request_field
        if response_field != "message":
            target_kwargs["response_field"] = response_field
        if param_field:
            target_kwargs["param_field"] = param_field
        if request_delay > 0:
            target_kwargs["request_delay"] = request_delay

    try:
        llm_target = create_target(target, **target_kwargs)
    except Exception as e:
        console.print(f"[red]Error creating target: {e}[/red]")
        sys.exit(1)

    attack_list = attacks.split(",") if attacks else None

    # Load external plugin files and discover installed entry-point plugins.
    from vektor.core.plugin import load_plugin_file, discover_entry_points
    for plugin_path in plugins:
        try:
            n = load_plugin_file(plugin_path)
            if not ci:
                console.print(f"[green]Loaded {n} attack(s) from {plugin_path}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to load plugin {plugin_path}: {e}[/red]")

    scanner = VektorScanner(llm_target, budget_limit=budget)

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
            results = scanner.scan(attacks=attack_list, quick_mode=quick, mode=mode)
            progress.update(task, completed=len(results.get("all_results", [])))
    else:
        results = scanner.scan(attacks=attack_list, quick_mode=quick, mode=mode)

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
@click.version_option(version=__version__, prog_name="vektor")
@click.pass_context
def cli(ctx):
    """Vektor: AI Security Testing Framework."""
    if ctx.invoked_subcommand is None:
        _run_wizard()


@cli.command()
@click.option("--target", type=click.Choice(PROVIDERS), default=None, help="LLM provider to scan (omit when using --url)")
@click.option("--url", default=None, help="HTTP endpoint URL to scan (e.g. http://localhost:8000/chat)")
@click.option("--header", "headers", multiple=True, metavar="KEY:VALUE", help="Request header (repeatable): --header \"Authorization: Bearer tok_xxx\"")
@click.option("--param-field", default=None, help="Send prompt as URL query param instead of JSON body (e.g. --param-field text)")
@click.option("--request-delay", default=0.0, type=float, show_default=True, help="Seconds to wait between requests (for rate-limited APIs, e.g. 4.0 for Gemini free tier)")
@click.option("--request-field", default="message", show_default=True, help="JSON key for the prompt in simple-shape requests")
@click.option("--response-field", default="message", show_default=True, help="JSON key to extract from simple-shape responses")
@click.option("--model", default=None, help="Model name (uses provider default if omitted)")
@click.option("--system-prompt", default=None, help="System prompt string")
@click.option("--system-prompt-file", default=None, type=click.Path(exists=True), help="Path to system prompt file")
@click.option("--budget", default=1.0, type=float, help="Max budget in USD (default: 1.0)")
@click.option("--output", default="report.json", help="Output file path (default: report.json)")
@click.option("--ci", is_flag=True, help="CI mode: JSON to stdout, no colors, no progress bar")
@click.option("--quick", is_flag=True, help="Quick mode: only run high-success-rate attacks")
@click.option("--mode", type=click.Choice(["standard", "analysis"]), default="standard", show_default=True,
            help="Scan mode. analysis prioritizes error leaks, response anomalies, and internal system signals.")
@click.option("--attacks", default=None, help="Comma-separated list of attack IDs to run")
@click.option("--api-key", default=None, help="API key (or set env var: OPENAI_API_KEY, GROQ_API_KEY, etc.)")
@click.option("--base-url", default=None, help="Override endpoint URL for OpenAI-compat providers (e.g. http://localhost:5000/v1)")
@click.option("--plugin", "plugins", multiple=True, metavar="PATH",
              help="Load external attack plugin file (repeatable). e.g. --plugin ./my_attacks.py")
def scan(target, url, headers, param_field, request_delay, request_field, response_field, model, system_prompt,
        system_prompt_file, budget, output, ci, quick, mode, attacks, api_key, base_url, plugins):
    """Run a security scan against an LLM target.

    \b
    Examples:
      vektor scan --target groq
      vektor scan --url http://localhost:8000/chat
      vektor scan --url https://my-app.com/api/chat --header "Authorization: Bearer tok_xxx"
      vektor scan --url http://localhost:3000/api --request-field input --response-field output
    """
    if not target and not url:
        raise click.UsageError("Provide --target <provider> or --url <endpoint>.")

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
        base_url=base_url,
        url=url,
        headers=headers,
        param_field=param_field,
        request_delay=request_delay,
        request_field=request_field,
        response_field=response_field,
        plugins=plugins,
        mode=mode,
    )


@cli.command()
def demo():
    """Run demo mode - no API key needed. Shows sample scan results."""
    from vektor.demo import run_demo
    run_demo(console)


@cli.command("list")
def list_attacks():
    """List all available attacks grouped by category."""
    from vektor.attacks.registry import ATTACK_REGISTRY, get_categories

    table = Table(title="vektor Attacks", show_header=True, header_style="bold cyan")
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
    from vektor.attacks.registry import ATTACK_REGISTRY

    if attack_id not in ATTACK_REGISTRY:
        console.print(f"[red]Unknown attack: {attack_id}[/red]")
        console.print("[dim]Run 'vektor list' to see available attacks.[/dim]")
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


@cli.command()
@click.argument("v1", metavar="REPORT_V1")
@click.argument("v2", metavar="REPORT_V2")
@click.option("--output", default=None,
              help="Save JSON (+ HTML) diff to this path, e.g. diff.json")
@click.option("--fail-on", "fail_on",
              type=click.Choice(["regression", "new_vuln", "any"], case_sensitive=False),
              default=None,
              help="Exit with code 1 when the given condition is met (for CI).")
@click.option("--ci", is_flag=True,
              help="CI mode: JSON output to stdout, no colours.")
def diff(v1, v2, output, fail_on, ci):
    """Compare two scan reports and show regressions.

    \b
    Examples:
      vektor diff scan_v1.json scan_v2.json
      vektor diff scan_v1.json scan_v2.json --output diff.json
      vektor diff scan_v1.json scan_v2.json --fail-on regression
      vektor diff scan_v1.json scan_v2.json --fail-on any --ci
    """
    import json as _json
    from vektor.core.diff import (
        diff_reports, print_diff_table, has_regression,
        save_diff_json, save_diff_html, to_dict,
        STATUS_REGRESSED, STATUS_NEW,
    )

    try:
        diffs = diff_reports(v1, v2)
    except FileNotFoundError as exc:
        console.print(f"[red]File not found: {exc}[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error loading reports: {exc}[/red]")
        sys.exit(1)

    if ci:
        payload = {
            "v1": v1, "v2": v2,
            "regressions": has_regression(diffs),
            "diffs": to_dict(diffs),
        }
        click.echo(_json.dumps(payload, indent=2))
    else:
        print_diff_table(diffs, v1, v2, console=console)

    if output:
        save_diff_json(diffs, v1, v2, output)
        html_path = output.replace(".json", ".html")
        save_diff_html(diffs, v1, v2, html_path)
        if not ci:
            console.print(f"[green]Diff saved:[/green] {output}, {html_path}")

    if fail_on:
        regressed = any(d.status == STATUS_REGRESSED for d in diffs)
        new_vulns = any(d.status == STATUS_NEW       for d in diffs)
        should_fail = (
            (fail_on == "regression" and regressed)
            or (fail_on == "new_vuln"  and new_vulns)
            or (fail_on == "any"       and (regressed or new_vulns))
        )
        if should_fail:
            if not ci:
                console.print("[bold red]\nCI check failed: regressions or new vulnerabilities found.[/bold red]")
            sys.exit(1)


if __name__ == "__main__":
    cli()
