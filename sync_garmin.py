#!/usr/bin/env python3
"""
sync_garmin.py
Pulls Garmin Connect wellness + activity data and writes it into a clean
folder structure that an LLM (or your dashboard) can read directly.

Setup:
    pip install garminconnect garth

Auth (run once, interactively, to create a reusable token):
    export GARMIN_EMAIL="you@example.com"
    export GARMIN_PASSWORD="your-password"
    python sync_garmin.py --login

    This saves a token bundle to ~/.garmin_tokens (or --token-dir).
    Garmin sometimes requires an MFA code the first time — you'll be
    prompted for it in the terminal. After this, --login is not needed
    again until the token expires (Garmin tokens are long-lived, ~1 year).

Daily pull (what cron / GitHub Actions will run):
    python sync_garmin.py --days 3

Dry run (pull data, print summary, don't write files):
    python sync_garmin.py --days 3 --dry-run

Output layout (default ./garmin/):
    garmin/
      daily/2026-06-28.md        # one wellness note per day, plain English
      activities/2026-06-28-....md   # one note per workout
      data.json                  # full structured store, updated each run
"""

import argparse
import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

try:
    from garminconnect import Garmin
except ImportError:
    print("Missing dependency. Run: pip install garminconnect garth", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def get_client(token_dir: Path, do_login: bool) -> Garmin:
    """
    Returns an authenticated Garmin client, reusing a cached token if present.

    Note: garminconnect's login(tokenstore=...) handles loading an existing
    token AND saving a new one after a credential login, all in one call —
    there's no separate "dump" step needed.
    """
    token_dir.mkdir(parents=True, exist_ok=True)
    token_path = str(token_dir)

    if not do_login:
        client = Garmin()
        try:
            client.login(tokenstore=token_path)
        except Exception:
            print("No valid cached token found — run with --login first.", file=sys.stderr)
            sys.exit(1)
        return client

    email = os.environ.get("GARMIN_EMAIL")
    password = os.environ.get("GARMIN_PASSWORD")
    if not email or not password:
        print("GARMIN_EMAIL and GARMIN_PASSWORD must be set for --login.", file=sys.stderr)
        sys.exit(1)

    client = Garmin(
        email=email,
        password=password,
        prompt_mfa=lambda: input("Enter the MFA code Garmin sent you: ").strip(),
    )
    client.login(tokenstore=token_path)
    print(f"Login token saved to {token_path}")
    return client


# ---------------------------------------------------------------------------
# Data pulls
# ---------------------------------------------------------------------------

def pull_day_wellness(client: Garmin, day: date) -> dict:
    d = day.isoformat()
    out = {"date": d}

    try:
        summary = client.get_user_summary(d)
        out["resting_hr"] = summary.get("restingHeartRate")
        out["steps"] = summary.get("totalSteps")
        out["stress_avg"] = summary.get("averageStressLevel")
        out["body_battery_start"] = summary.get("bodyBatteryMostRecentValue")
    except Exception:
        pass

    try:
        sleep = client.get_sleep_data(d)
        dto = sleep.get("dailySleepDTO", {})
        seconds = dto.get("sleepTimeSeconds")
        out["sleep_hours"] = round(seconds / 3600, 1) if seconds else None
        out["sleep_score"] = (dto.get("sleepScores") or {}).get("overall", {}).get("value")
    except Exception:
        pass

    try:
        hrv = client.get_hrv_data(d)
        summ = (hrv or {}).get("hrvSummary", {})
        out["hrv_overnight_ms"] = summ.get("lastNightAvg")
    except Exception:
        pass

    try:
        tr = client.get_training_readiness(d)
        if isinstance(tr, list) and tr:
            out["training_readiness"] = tr[0].get("score")
    except Exception:
        pass

    try:
        bb = client.get_body_battery(d, d)
        if isinstance(bb, list) and bb:
            vals = bb[0].get("bodyBatteryValuesArray") or []
            if vals:
                out["body_battery_low"] = min(v[1] for v in vals if v[1] is not None)
                out["body_battery_high"] = max(v[1] for v in vals if v[1] is not None)
    except Exception:
        pass

    return out


def pull_activities(client: Garmin, start: date, end: date) -> list:
    activities = client.get_activities_by_date(start.isoformat(), end.isoformat())
    return activities or []


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

# Garmin Connect activityType.typeKey -> this dashboard's sport vocabulary
# (Run/Bike/Swim/Strength/Recovery, matching workouts.json). Unmapped types
# (e.g. multi_sport) are skipped rather than guessed.
GARMIN_TYPE_TO_SPORT = {
    "running": "Run", "treadmill_running": "Run", "trail_running": "Run",
    "track_running": "Run", "indoor_running": "Run", "street_running": "Run",
    "cycling": "Bike", "road_biking": "Bike", "indoor_cycling": "Bike",
    "virtual_ride": "Bike", "mountain_biking": "Bike", "gravel_cycling": "Bike",
    "cyclocross": "Bike", "track_cycling": "Bike",
    "lap_swimming": "Swim", "open_water_swimming": "Swim", "pool_swim": "Swim",
    "strength_training": "Strength",
    "walking": "Recovery", "hiking": "Recovery",
}


def write_dashboard_garmin_activities_json(repo_root: Path, activities: list):
    """
    Writes garmin_activities.json at the repo root in the same shape as
    workouts.json ({syncedAt, source, workouts: [{date, sport, duration,
    distance, notes}]}) so plan.html can merge it straight into its existing
    Strava-sourced workout list. Keyed internally by activityId so re-running
    with an overlapping --days window doesn't create duplicate entries.
    """
    path = repo_root / "garmin_activities.json"
    by_id = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            by_id = {str(w["activityId"]): w for w in existing.get("workouts", []) if w.get("activityId") is not None}
        except Exception:
            by_id = {}

    for a in activities:
        sport = GARMIN_TYPE_TO_SPORT.get((a.get("activityType") or {}).get("typeKey"))
        if not sport:
            continue
        distance_m = a.get("distance") or 0
        by_id[str(a.get("activityId"))] = {
            "activityId": a.get("activityId"),
            "date": (a.get("startTimeLocal") or "")[:10],
            "sport": sport,
            "duration": round((a.get("duration") or 0) / 60, 1),
            "distance": round(distance_m / 1609.34, 2) if distance_m else None,
            "notes": a.get("activityName"),
        }

    workouts = sorted(by_id.values(), key=lambda w: w["date"])
    out = {
        "syncedAt": datetime.now().isoformat() + "Z",
        "source": "Garmin Connect (sync_garmin.py)",
        "workouts": workouts,
    }
    path.write_text(json.dumps(out, indent=2, default=str))
    return path

def write_daily_note(out_dir: Path, wellness: dict):
    d = wellness["date"]
    path = out_dir / "daily" / f"{d}.md"
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [f"# Garmin wellness {d}", ""]
    if wellness.get("resting_hr") is not None:
        lines.append(f"- Resting HR: {wellness['resting_hr']} bpm")
    if wellness.get("hrv_overnight_ms") is not None:
        lines.append(f"- HRV (overnight): {wellness['hrv_overnight_ms']} ms")
    if wellness.get("sleep_hours") is not None:
        score = f" (score {wellness['sleep_score']})" if wellness.get("sleep_score") else ""
        lines.append(f"- Sleep: {wellness['sleep_hours']} h{score}")
    if wellness.get("body_battery_low") is not None:
        lines.append(f"- Body battery: {wellness['body_battery_low']} → {wellness['body_battery_high']}")
    if wellness.get("stress_avg") is not None:
        lines.append(f"- Stress (avg): {wellness['stress_avg']}")
    if wellness.get("steps") is not None:
        lines.append(f"- Steps: {wellness['steps']}")
    if wellness.get("training_readiness") is not None:
        lines.append(f"- Training readiness: {wellness['training_readiness']}")

    path.write_text("\n".join(lines) + "\n")
    return path


def write_activity_note(out_dir: Path, act: dict):
    start = act.get("startTimeLocal", "")[:10] or "unknown-date"
    name = (act.get("activityName") or "activity").replace("/", "-").replace(" ", "-")
    path = out_dir / "activities" / f"{start}-{name}.md"
    path.parent.mkdir(parents=True, exist_ok=True)

    dist_km = round((act.get("distance") or 0) / 1000, 2)
    dur_min = round((act.get("duration") or 0) / 60, 1)

    lines = [
        f"# {act.get('activityName', 'Activity')} — {start}",
        "",
        f"- Type: {(act.get('activityType') or {}).get('typeKey', 'unknown')}",
        f"- Distance: {dist_km} km",
        f"- Duration: {dur_min} min",
    ]
    if act.get("averageHR"):
        lines.append(f"- Avg HR: {act['averageHR']} bpm")
    if act.get("maxHR"):
        lines.append(f"- Max HR: {act['maxHR']} bpm")
    if act.get("averageSpeed"):
        lines.append(f"- Avg speed: {round(act['averageSpeed'] * 3.6, 2)} km/h")
    if act.get("calories"):
        lines.append(f"- Calories: {act['calories']}")
    if act.get("trainingEffectLabel"):
        lines.append(f"- Training effect: {act['trainingEffectLabel']}")

    path.write_text("\n".join(lines) + "\n")
    return path


def update_data_json(out_dir: Path, wellness_records: list, activities: list):
    path = out_dir / "data.json"
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except Exception:
            existing = {}

    existing.setdefault("daily", {})
    existing.setdefault("activities", {})

    for w in wellness_records:
        existing["daily"][w["date"]] = w

    for a in activities:
        aid = str(a.get("activityId"))
        existing["activities"][aid] = a

    existing["last_updated"] = datetime.now().isoformat()
    path.write_text(json.dumps(existing, indent=2, default=str))
    return path


def write_dashboard_garmin_json(repo_root: Path, wellness_records: list):
    """
    Writes garmin.json at the repo root in the same shape as the dashboard's
    existing whoop.json, so index.html can fetch() it directly:
        { "syncedAt": ..., "source": ..., "entries": [ {date, restingHr, hrv,
          sleepHours, sleepScore, bodyBatteryLow, bodyBatteryHigh, stressAvg,
          steps, trainingReadiness}, ... ] }

    Merges with whatever is already in garmin.json rather than overwriting,
    same as how whoop.json accumulates entries over time.
    """
    path = repo_root / "garmin.json"
    existing = {"entries": []}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except Exception:
            existing = {"entries": []}

    by_date = {e["date"]: e for e in existing.get("entries", [])}

    for w in wellness_records:
        by_date[w["date"]] = {
            "date": w["date"],
            "restingHr": w.get("resting_hr"),
            "hrv": w.get("hrv_overnight_ms"),
            "sleepHours": w.get("sleep_hours"),
            "sleepScore": w.get("sleep_score"),
            "bodyBatteryLow": w.get("body_battery_low"),
            "bodyBatteryHigh": w.get("body_battery_high"),
            "stressAvg": w.get("stress_avg"),
            "steps": w.get("steps"),
            "trainingReadiness": w.get("training_readiness"),
        }

    entries = sorted(by_date.values(), key=lambda e: e["date"])

    out = {
        "syncedAt": datetime.now().isoformat() + "Z",
        "source": "Garmin Connect (sync_garmin.py)",
        "entries": entries,
    }
    path.write_text(json.dumps(out, indent=2, default=str))
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Sync Garmin Connect data to local files.")
    parser.add_argument("--login", action="store_true", help="Force an interactive login and refresh the saved token.")
    parser.add_argument("--days", type=int, default=3, help="How many days back to pull (default 3).")
    parser.add_argument("--out-dir", default="garmin", help="Output directory (default ./garmin).")
    parser.add_argument("--repo-root", default=".", help="tri-dashboard repo root — where garmin.json is written (default: current directory).")
    parser.add_argument("--token-dir", default=os.path.expanduser("~/.garmin_tokens"), help="Where the login token is cached.")
    parser.add_argument("--dry-run", action="store_true", help="Pull and print data without writing files.")
    args = parser.parse_args()

    client = get_client(Path(args.token_dir), args.login)

    if args.login and not args.days:
        return  # login-only invocation

    end = date.today()
    start = end - timedelta(days=args.days - 1)

    out_dir = Path(args.out_dir)
    wellness_records = []

    print(f"Pulling {args.days} day(s) of wellness data: {start} to {end}")
    d = start
    while d <= end:
        w = pull_day_wellness(client, d)
        wellness_records.append(w)
        if args.dry_run:
            print(json.dumps(w, indent=2))
        else:
            path = write_daily_note(out_dir, w)
            print(f"  wrote {path}")
        d += timedelta(days=1)

    if not args.dry_run:
        gj_path = write_dashboard_garmin_json(Path(args.repo_root), wellness_records)
        print(f"  updated {gj_path} for the dashboard")

    print(f"Pulling activities: {start} to {end}")
    activities = pull_activities(client, start, end)
    print(f"  found {len(activities)} activities")
    if not args.dry_run:
        for a in activities:
            path = write_activity_note(out_dir, a)
            print(f"  wrote {path}")
        json_path = update_data_json(out_dir, wellness_records, activities)
        print(f"  updated {json_path}")
        ga_path = write_dashboard_garmin_activities_json(Path(args.repo_root), activities)
        print(f"  updated {ga_path} for the dashboard")
    else:
        for a in activities:
            print(f"  - {a.get('startTimeLocal', '')[:10]}  {a.get('activityName')}")

    print("Done.")


if __name__ == "__main__":
    main()
