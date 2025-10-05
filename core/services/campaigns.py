from __future__ import annotations

from typing import Optional

from core.clients.api import get_campaigns as teneo_get_campaigns


async def get_status(email: str, token: str, name: str, proxy: Optional[str], log):
    campaigns = await teneo_get_campaigns(token, proxy)
    # First, try exact match
    for c in campaigns:
        if isinstance(c, dict) and c.get("campaignName") == name:
            completed = c.get("completed", False)
            claimable = c.get("claimable", False)
            if completed:
                return True
            if claimable:
                return "claimable"
            return False
    
    # If no exact match, try partial match for X/Twitter campaigns
    if "X" in name or "Twitter" in name or "Engage" in name:
        for c in campaigns:
            if isinstance(c, dict):
                campaign_name = c.get("campaignName", "")
                # Check for partial matches
                if ("Engage" in campaign_name and "X" in campaign_name) or \
                   ("Twitter" in campaign_name) or \
                   ("Engage on X" in campaign_name):
                    completed = c.get("completed", False)
                    claimable = c.get("claimable", False)
                    log(f"Found campaign match: '{campaign_name}' for query '{name}' - completed={completed}, claimable={claimable}")
                    if completed:
                        return True
                    if claimable:
                        return "claimable"
                    return False
    
    log(f"Campaign '{name}' not found for {email}")
    return False


