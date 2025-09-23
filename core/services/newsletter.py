from __future__ import annotations

from typing import Optional

from core.clients.api import subscribe_newsletter as teneo_subscribe_newsletter


async def subscribe(email: str, token: str, proxy: Optional[str], log) -> bool:
    """Подписка на новости Teneo Protocol Newsletter"""
    try:
        log(f"Subscribing to Teneo Protocol Newsletter for {email}...")
        
        response = await teneo_subscribe_newsletter(token, proxy)
        
        if response.get("success") and response.get("points") == 5000:
            points = response.get("points", 0)
            log(f"Successfully subscribed to newsletter for {email}. Points earned: {points}")
            return True
        else:
            log(f"Failed to subscribe to newsletter for {email}: {response}")
            return False
            
    except Exception as e:
        log(f"Error subscribing to newsletter for {email}: {e}")
        return False