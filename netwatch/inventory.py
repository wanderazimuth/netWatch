"""What each device is and where it lives: review status, type, floor, room, person and notes."""

from __future__ import annotations

import time

# "review" is stored as NULL: every device starts out to be reviewed.
STATUSES = ("review", "known", "guest")
FLOORS = ("Upstairs", "Main floor", "Basement", "Outside")
# The dashboard has a label and an icon for each.
KINDS = ("phone", "tablet", "computer", "tv", "speaker", "camera", "smart_home", "appliance", "printer",
         "console", "wearable", "network", "server", "other")
MAX_LABEL, MAX_ROOM, MAX_NOTES = 64, 40, 500
FIELDS = ("label", "status", "kind", "floor", "room", "person", "notes")


def _text(body: dict, key: str, limit: int) -> str | None:
    value = body[key]
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be text or null")
    return (value or "").strip()[:limit] or None


def clean(body: dict, people: list[str], current_person: str | None = None, now: int | None = None) -> dict:
    """The device columns to update from a review form, or raise ValueError naming the bad field.

    Only the fields present in body change, so an alert button can set just the status.
    """
    unknown = set(body) - set(FIELDS)
    if unknown:
        raise ValueError(f"unknown field {sorted(unknown)[0]!r}")
    out = {}
    if "label" in body:
        out["label"] = _text(body, "label", MAX_LABEL)
    if "room" in body:
        out["room"] = _text(body, "room", MAX_ROOM)
    if "notes" in body:
        out["notes"] = _text(body, "notes", MAX_NOTES)
    for key, allowed in (("kind", KINDS), ("floor", FLOORS)):
        if key in body:
            if body[key] is not None and body[key] not in allowed:
                raise ValueError(f"{key} must be one of {', '.join(allowed)}, or null")
            out[key] = body[key]
    if "person" in body:
        # Someone taken off the people list stays on the devices they already had.
        if body["person"] is not None and body["person"] not in people and body["person"] != current_person:
            raise ValueError("person must be someone on the people list, or null")
        out["person"] = body["person"]
    if "status" in body:
        if body["status"] not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        reviewed = body["status"] != "review"
        out["status"] = body["status"] if reviewed else None
        out["reviewed"] = (now or int(time.time())) if reviewed else None
    return out


# Moved from the old MAC to the new one, unless the new one already has its own.
CARRIED = ("label", "kind", "floor", "room", "person", "notes", "down_after")


def merge(conn, old: str, new: str) -> None:
    """Make new the same device as old, for a phone that rotated its private MAC.

    The new MAC gets the old one's name, details, alerts and history (events and internet use),
    and the old entry goes.
    Raises LookupError for an unknown MAC and ValueError when they can't be merged.
    """
    if old == new:
        raise ValueError("a device can't be the same device as itself")
    rows = {r["mac"]: r for r in conn.execute("SELECT * FROM devices WHERE mac IN (?, ?)", (old, new))}
    if old not in rows or new not in rows:
        raise LookupError("unknown device")
    o, n = rows[old], rows[new]
    if o["paused_ip"]:
        # Its Pi-hole block would be left behind with nobody to lift it.
        raise ValueError("resume the old device's internet first")
    updates = {k: o[k] if n[k] is None else n[k] for k in CARRIED}
    # Status and when it was given go together.
    updates.update({k: (n if n["status"] else o)[k] for k in ("status", "reviewed")})
    updates["notify"] = max(o["notify"], n["notify"])
    updates["first_seen"] = min(o["first_seen"], n["first_seen"])
    conn.execute(f"UPDATE devices SET {', '.join(k + ' = ?' for k in updates)} WHERE mac = ?", (*updates.values(), new))
    conn.execute("UPDATE events SET mac = ? WHERE mac = ?", (new, old))
    conn.execute("UPDATE traffic SET mac = ? WHERE mac = ?", (new, old))
    # Open ports belong to the old address; the new one gets its own scan.
    conn.execute("DELETE FROM ports WHERE mac = ?", (old,))
    conn.execute("DELETE FROM devices WHERE mac = ?", (old,))
    conn.commit()
