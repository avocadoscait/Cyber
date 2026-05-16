"""
B24 - Attribute-Based Access Control (ABAC)
===========================================
ABAC makes access decisions based on attributes of:
  - The SUBJECT (user): department, clearance, role, location
  - The RESOURCE: classification, owner, department
  - The ENVIRONMENT: time of day, day of week
  - The ACTION: read, write, delete, approve

Policies are expressed as rules combining these attributes.
This is more expressive than RBAC — the same user can be
granted or denied access based on context, not just role.
"""

import datetime

# ─────────────────────────────────────────────
# ATTRIBUTE DEFINITIONS
# ─────────────────────────────────────────────

# Clearance levels (higher = more access)
CLEARANCE = {"public": 0, "internal": 1, "confidential": 2, "secret": 3}

# Subjects (users) with their attributes
SUBJECTS = {
    "alice": {"department": "engineering", "clearance": "secret",       "role": "engineer",  "location": "office"},
    "bob":   {"department": "finance",     "clearance": "confidential", "role": "analyst",   "location": "office"},
    "carol": {"department": "hr",          "clearance": "internal",     "role": "recruiter", "location": "remote"},
    "dave":  {"department": "engineering", "clearance": "internal",     "role": "intern",    "location": "office"},
    "eve":   {"department": "management",  "clearance": "secret",       "role": "director",  "location": "office"},
}

# Resources with their attributes
RESOURCES = {
    "design_doc":      {"classification": "confidential", "department": "engineering", "type": "document"},
    "payroll_data":    {"classification": "secret",       "department": "finance",     "type": "database"},
    "job_postings":    {"classification": "public",       "department": "hr",          "type": "document"},
    "intern_handbook": {"classification": "internal",     "department": "hr",          "type": "document"},
    "source_code":     {"classification": "confidential", "department": "engineering", "type": "repository"},
    "board_report":    {"classification": "secret",       "department": "management",  "type": "document"},
}

# ─────────────────────────────────────────────
# POLICY RULES
# Each policy is a function that returns (permit, reason)
# ─────────────────────────────────────────────

def policy_clearance_level(subject, resource, action, env):
    """Subject clearance must meet or exceed resource classification."""
    subject_level   = CLEARANCE.get(subject.get("clearance", "public"), 0)
    resource_level  = CLEARANCE.get(resource.get("classification", "public"), 0)
    if subject_level >= resource_level:
        return True, "Clearance level sufficient"
    return False, f"Insufficient clearance: {subject['clearance']} < {resource['classification']}"


def policy_department_match(subject, resource, action, env):
    """Write/delete actions require matching departments (or management role)."""
    if action in ("read",):
        return True, "Read — department match not required"
    if subject.get("role") == "director":
        return True, "Director role bypasses department restriction"
    if subject.get("department") == resource.get("department"):
        return True, "Department match confirmed"
    return False, f"Department mismatch: user={subject['department']}, resource={resource['department']}"


def policy_business_hours(subject, resource, action, env):
    """Secret resources can only be accessed during business hours (Mon-Fri, 8am-6pm)."""
    if resource.get("classification") != "secret":
        return True, "Resource is not secret — hours restriction not applied"
    hour     = env.get("hour", 12)
    weekday  = env.get("weekday", 0)
    if weekday >= 5:
        return False, "Secret resources not accessible on weekends"
    if not (8 <= hour < 18):
        return False, f"Secret resources only accessible 08:00-18:00 (current hour: {hour}:00)"
    return True, "Access within business hours"


def policy_no_remote_write(subject, resource, action, env):
    """Remote users cannot perform write or delete actions on confidential/secret resources."""
    if action not in ("write", "delete"):
        return True, "Action is read — remote restriction not applied"
    if subject.get("location") != "remote":
        return True, "User is not remote"
    level = CLEARANCE.get(resource.get("classification", "public"), 0)
    if level >= CLEARANCE["internal"]:
        return False, "Remote users cannot write to internal or higher classification resources"
    return True, "Resource classification permits remote write"


def policy_intern_restriction(subject, resource, action, env):
    """Interns can only read public and internal resources."""
    if subject.get("role") != "intern":
        return True, "User is not an intern"
    level = CLEARANCE.get(resource.get("classification", "public"), 0)
    if level >= CLEARANCE["confidential"]:
        return False, "Interns cannot access confidential or secret resources"
    if action in ("write", "delete"):
        return False, "Interns have read-only access"
    return True, "Intern read access to non-confidential resource permitted"


POLICIES = [
    policy_clearance_level,
    policy_department_match,
    policy_business_hours,
    policy_no_remote_write,
    policy_intern_restriction,
]

# ─────────────────────────────────────────────
# ABAC ENGINE
# ─────────────────────────────────────────────

def check_access(username, resource_name, action, env=None):
    if env is None:
        now = datetime.datetime.now()
        env = {"hour": now.hour, "weekday": now.weekday()}

    subject  = SUBJECTS.get(username)
    resource = RESOURCES.get(resource_name)

    if not subject:
        return False, "Unknown subject"
    if not resource:
        return False, "Unknown resource"

    for policy in POLICIES:
        permitted, reason = policy(subject, resource, action, env)
        if not permitted:
            return False, f"[{policy.__name__}] DENY: {reason}"

    return True, "All policies satisfied — ACCESS GRANTED"


# ─────────────────────────────────────────────
# EVALUATION TEST SUITE
# ─────────────────────────────────────────────

def run_evaluation():
    print("=" * 65)
    print("ABAC IMPLEMENTATION — EVALUATION TEST SUITE")
    print("=" * 65)

    passed = 0
    failed = 0

    BUSINESS_ENV = {"hour": 10, "weekday": 1}   # Tuesday 10am
    WEEKEND_ENV  = {"hour": 10, "weekday": 6}   # Saturday 10am
    EVENING_ENV  = {"hour": 20, "weekday": 1}   # Tuesday 8pm

    tests = [
        # (desc, user, resource, action, env, expected_permit)
        ("Alice (engineer, secret) reads design_doc",            "alice", "design_doc",   "read",   BUSINESS_ENV, True),
        ("Alice reads payroll_data (wrong dept, write)",         "alice", "payroll_data", "write",  BUSINESS_ENV, False),
        ("Alice reads board_report (secret, business hours)",    "alice", "board_report", "read",   BUSINESS_ENV, True),
        ("Alice reads board_report on weekend",                  "alice", "board_report", "read",   WEEKEND_ENV,  False),
        ("Alice reads board_report after hours",                 "alice", "board_report", "read",   EVENING_ENV,  False),
        ("Bob (finance, confidential) reads payroll_data",       "bob",   "payroll_data", "read",   BUSINESS_ENV, False),  # secret > confidential
        ("Bob writes job_postings (wrong dept)",                 "bob",   "job_postings", "write",  BUSINESS_ENV, False),
        ("Carol (hr, internal, remote) reads intern_handbook",   "carol", "intern_handbook","read", BUSINESS_ENV, True),
        ("Carol (remote) writes intern_handbook",                "carol", "intern_handbook","write",BUSINESS_ENV, False),  # remote write denied
        ("Carol reads design_doc (wrong dept + clearance)",      "carol", "design_doc",   "read",   BUSINESS_ENV, False),
        ("Dave (intern) reads job_postings (public)",            "dave",  "job_postings", "read",   BUSINESS_ENV, True),
        ("Dave (intern) reads design_doc (confidential)",        "dave",  "design_doc",   "read",   BUSINESS_ENV, False),
        ("Dave (intern) writes intern_handbook",                 "dave",  "intern_handbook","write",BUSINESS_ENV, False),
        ("Eve (director, secret) reads payroll_data",            "eve",   "payroll_data", "read",   BUSINESS_ENV, True),
        ("Eve (director) writes source_code (diff dept)",        "eve",   "source_code",  "write",  BUSINESS_ENV, True),   # director bypasses dept
        ("Eve reads board_report on weekend",                    "eve",   "board_report", "read",   WEEKEND_ENV,  False),
    ]

    for desc, user, resource, action, env, expected in tests:
        result, reason = check_access(user, resource, action, env)
        ok = result == expected
        if ok: passed += 1
        else:  failed += 1
        icon = "PASS" if ok else "FAIL"
        outcome = "PERMIT" if result else "DENY  "
        print(f"  [{icon}] {outcome} | {desc}")
        if not ok:
            print(f"         Expected: {'PERMIT' if expected else 'DENY'} | Reason: {reason}")

    print(f"\n{'='*65}")
    print(f"RESULTS: {passed}/{passed+failed} tests passed")
    if failed == 0:
        print("All tests passed ✓ — ABAC implementation functioning correctly.")
    print("="*65)


if __name__ == "__main__":
    run_evaluation()
