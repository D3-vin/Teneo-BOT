from __future__ import annotations

from typing import Optional, List, Dict, Any

from core.clients.api import get_heartbeat_status as teneo_get_heartbeat_status, claim_streak as teneo_claim_streak
from colorama import Fore, Style


async def get_claimable_streaks(email: str, token: str, proxy: Optional[str], log) -> List[Dict[str, Any]]:
    """Получить доступные для клейма стрики"""
    try:
        log(f"{Fore.CYAN}Getting heartbeat status for {email}...{Fore.RESET}")
        
        campaigns = await teneo_get_heartbeat_status(token, proxy)
        
        if not campaigns:
            log(f"{Fore.YELLOW}No heartbeat campaigns found for {email}{Fore.RESET}")
            return []
        
        # Фильтруем только кампании со статусом "claimable"
        claimable_campaigns = []
        if isinstance(campaigns, list):
            for campaign in campaigns:
                if isinstance(campaign, dict) and campaign.get("status") == "claimable":
                    claimable_campaigns.append(campaign)
        
        if claimable_campaigns:
            log(f"{Fore.GREEN}Found {len(claimable_campaigns)} claimable streaks for {email}{Fore.RESET}")
            
            # Выводим информацию о каждом доступном стрике
            for campaign in claimable_campaigns:
                campaign_id = campaign.get("id", "Unknown")
                title = campaign.get("title", "Unknown")
                points_reward = campaign.get("points_reward", 0)
                streak_days = campaign.get("requirements", {}).get("streak_days", 0)
                min_heartbeat = campaign.get("requirements", {}).get("min_heartbeat", 0)
                
                log(f"{Fore.CYAN}  - {title}: {streak_days} days, {min_heartbeat} HB, reward: {points_reward} points (ID: {campaign_id}){Fore.RESET}")
        else:
            log(f"{Fore.YELLOW}No claimable streaks found for {email}{Fore.RESET}")
            
        return claimable_campaigns
        
    except Exception as e:
        log(f"{Fore.RED}Error getting heartbeat status for {email}: {e}{Fore.RESET}")
        return []


async def claim_all_streaks(email: str, token: str, proxy: Optional[str], log) -> int:
    """Заклеймить все доступные стрики и вернуть количество успешных клеймов"""
    try:
        # Получаем доступные стрики
        claimable_streaks = await get_claimable_streaks(email, token, proxy, log)
        
        if not claimable_streaks:
            return 0
            
        claimed_count = 0
        
        # Клеймим каждый доступный стрик
        for streak in claimable_streaks:
            streak_id = streak.get("id")
            title = streak.get("title", "Unknown")
            points_reward = streak.get("points_reward", 0)
            
            if not streak_id:
                log(f"{Fore.RED}No streak ID found for {title}{Fore.RESET}")
                continue
                
            try:
                log(f"{Fore.CYAN}Claiming streak '{title}' for {email}...{Fore.RESET}")
                
                response = await teneo_claim_streak(token, streak_id, proxy)
                
                if response.get("success") and response.get("status") == 200:
                    claimed_count += 1
                    log(f"{Fore.GREEN}Successfully claimed '{title}' for {email} - {points_reward} points earned{Fore.RESET}")
                else:
                    log(f"{Fore.RED}Failed to claim '{title}' for {email}: {response}{Fore.RESET}")
                    
            except Exception as e:
                log(f"{Fore.RED}Error claiming streak '{title}' for {email}: {e}{Fore.RESET}")
                
        return claimed_count
        
    except Exception as e:
        log(f"{Fore.RED}Error claiming streaks for {email}: {e}{Fore.RESET}")
        return 0