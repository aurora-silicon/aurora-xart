# SPDX-License-Identifier: MIT
"""Which SEP profile the driver picks for a Mac, and its xART guard default.

Follows profile.rs `select` and each profile's `xart_guard` field.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    chip: str
    guard_default: int
    bootstrap: str  # "cold" or "warm"


T8103 = Profile("T8103/J313", "M1", 0, "cold")
T6000 = Profile("T6000/J316s", "M1 Pro/Max", 0, "cold")
T6020 = Profile("T6020/J414s", "M2 Pro/Max", 1, "warm")
T8140 = Profile("T8140/J700", "A18 Pro (MacBook Neo)", 0, "warm")
T8112 = Profile("T8112/J415", "M2", 1, "warm")
T8122 = Profile("T8122/J613", "M3", 1, "warm")
T6040 = Profile("T6040/J616s", "M4 Pro", 1, "warm")
T6041 = Profile("T6041/J616c", "M4 Max", 1, "warm")
T8132 = Profile("T8132/J713", "M4", 1, "warm")

CHIPS = {
    "t8103": "M1", "t6000": "M1 Pro", "t6001": "M1 Max", "t6002": "M1 Ultra",
    "t8112": "M2", "t6020": "M2 Pro", "t6021": "M2 Max", "t6022": "M2 Ultra",
    "t8122": "M3", "t6030": "M3 Pro", "t6031": "M3 Max", "t6034": "M3 Max",
    "t8132": "M4", "t6040": "M4 Pro", "t6041": "M4 Max", "t8140": "A18 Pro",
}


def select(compatible: list[str]) -> Profile | None:
    """profile.rs `select`, in its order."""
    has = set(compatible).__contains__
    if has("apple,t8103"):
        return T8103
    if has("apple,t6020") or has("apple,t6021"):
        return T6020
    if has("apple,t6000") or has("apple,t6001"):
        return T6000
    if has("apple,t8140"):
        return T8140
    if has("apple,t8112"):
        return T8112
    if has("apple,t8122") and (has("apple,j613") or has("apple,j615")):
        return T8122
    if has("apple,t6040") and (has("apple,j616s") or has("apple,j614s")):
        return T6040
    if has("apple,t6041") and has("apple,j616c"):
        return T6041
    if has("apple,t8132") and has("apple,j713"):
        return T8132
    return None


def chip(compatible: list[str]) -> str | None:
    for entry in compatible:
        name = CHIPS.get(entry.removeprefix("apple,"))
        if name:
            return name
    return None


def guard_level(param: int, platform_default: int) -> int:
    """xart_guard.rs `level`: 0 for no guard, else 1 or 2."""
    level = platform_default if param < 0 else param
    return min(level, 2)
