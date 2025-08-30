"""
Модуль для отображения красивого меню Teneo бота.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.prompt import Prompt


class TeneoMenu:
    """Класс для управления меню Teneo бота."""
    
    def __init__(self):
        self.console = Console()
    
    def display_welcome(self):
        """Отображает приветственный экран с логотипом."""
        self.console.clear()
        
        combined_text = Text()
        combined_text.append("\n📢 Channel: ", style="bold white")
        combined_text.append("https://t.me/D3_vin", style="cyan")
        combined_text.append("\n💬 Chat: ", style="bold white")
        combined_text.append("https://t.me/D3vin_chat", style="cyan")
        combined_text.append("\n📁 GitHub: ", style="bold white")
        combined_text.append("https://github.com/D3-vin", style="cyan")
        combined_text.append("\n📁 Version: ", style="bold white")
        combined_text.append("2.0", style="green")
        combined_text.append("\n")

        info_panel = Panel(
            Align.left(combined_text),
            title="[bold blue]Teneo Bot[/bold blue]",
            subtitle="[bold magenta]Dev by D3vin[/bold magenta]",
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(0, 1),
            width=50
        )

        self.console.print(info_panel)
        self.console.print()

    def display_menu(self):
        """Отображает главное меню с опциями."""
        table = Table(
            show_header=False,
            box=None,
            border_style="bright_blue",
            expand=False,
            width=50,
            padding=(0, 1)
        )
        
        table.add_column("Menu Options", style="white", justify="left")
        
        options = [
            "1 Registration",
            "2 Authorization", 
            "3 Farm",
            "4 Wallet Connection & Creating smart account",
            "5 Connect Twitter & Claim X Campaign",
            "6 Connect Discord & Claim Discord Campaign",
            "7 Exit"
        ]
        
        for option in options:
            table.add_row(f"[bold bright_cyan]{option}[/bold bright_cyan]")
        
        menu_panel = Panel(
            table,
            title="[bold blue]📋 Menu[/bold blue]",
            border_style="bright_blue",
            padding=(0, 1),
            width=50
        )
        
        self.console.print(menu_panel)
    
    def get_user_choice(self) -> int:
        """Получает выбор пользователя из меню."""
        while True:
            try:
                choice = Prompt.ask(
                    "\n[bold white]Choose action[/bold white] [1-7]",
                    choices=["1", "2", "3", "4", "5", "6", "7"],
                    default="1"
                )
                return int(choice)
            except ValueError:
                self.console.print("[red]Invalid input. Please enter a number from 1 to 7.[/red]")
    
    def display_operation_info(self, operation: str, account_count: int):
        """Отображает информацию о выбранной операции."""
        self.console.clear()
        self.display_welcome()
        self.console.print(f"\n[bold bright_cyan]Selected: {operation}[/bold bright_cyan]")
        self.console.print(f"[bold bright_cyan]Total accounts: {account_count}[/bold bright_cyan]")
        self.console.print()
    
    #def display_progress_header(self, operation: str, total_accounts: int):
    #    """Отображает заголовок для отображения прогресса."""
    #    self.console.print(f"\n[bold blue]🔄 Starting {operation} for {total_accounts} accounts...[/bold blue]")
    #    self.console.print("[bold cyan]" + "─" * 80 + "[/bold cyan]")
    
    def display_summary(self, operation: str, success_count: int, failed_count: int, total_count: int):
        """Отображает итоговую сводку операции."""
        self.console.print("\n[bold cyan]" + "─" * 80 + "[/bold cyan]")
        
        results_table = Table(
            title=f"[bold blue]📊 {operation} Results[/bold blue]",
            box=box.ROUNDED,
            border_style="bright_blue",
            width=80
        )
        
        results_table.add_column("Metric", style="bold white")
        results_table.add_column("Count", style="bold cyan")
        results_table.add_column("Percentage", style="bold green")
        
        results_table.add_row("Total Accounts", str(total_count), "100%")
        results_table.add_row("Successful", str(success_count), f"{(success_count/total_count*100):.1f}%")
        results_table.add_row("Failed", str(failed_count), f"{(failed_count/total_count*100):.1f}%")
        
        self.console.print(results_table)
        
        if failed_count == 0:
            self.console.print(f"\n[bold green]🎉 All {operation.lower()} operations completed successfully![/bold green]")
        else:
            self.console.print(f"\n[bold yellow]⚠️  {operation} completed with {failed_count} failures.[/bold yellow]")
            self.console.print("[bold cyan]Check result/ folder for failed accounts.[/bold cyan]")
    
    def display_message(self, message: str, message_type: str = "info"):
        """Отображает сообщение указанного типа."""
        colors = {
            "error": "red",
            "success": "green", 
            "warning": "yellow",
            "info": "cyan"
        }
        color = colors.get(message_type, "white")
        self.console.print(f"\n[bold {color}]{message}[/bold {color}]")
    
    def wait_for_key(self):
        """Ждет нажатия клавиши для продолжения."""
        self.console.print("\n[bold white]Press Enter to continue...[/bold white]")
        input()


# Глобальный экземпляр меню
_menu_instance: TeneoMenu | None = None


def get_menu() -> TeneoMenu:
    """Получает глобальный экземпляр меню."""
    global _menu_instance
    if _menu_instance is None:
        _menu_instance = TeneoMenu()
    return _menu_instance


def display_menu() -> int:
    """Отображает главное меню (для совместимости)."""
    menu = get_menu()
    menu.display_welcome()
    menu.display_menu()
    return menu.get_user_choice()


