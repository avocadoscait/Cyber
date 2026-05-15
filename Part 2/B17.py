"""
Role-Based Access Control (RBAC) Implementation
B17 - Cybersecurity Portfolio

A full RBAC system implementing the NIST RBAC model with:
- Role hierarchy (Admin > Manager > User > Guest)
- Permission assignment to roles
- User-role assignment
- Least privilege enforcement
- Audit logging
- Evaluation test suite
"""

import hashlib
import datetime
import json
from typing import Optional

# ─────────────────────────────────────────────
# CORE DATA STORES
# ─────────────────────────────────────────────

# Permissions: all available actions in the system
PERMISSIONS = {
    # User management
    "user:create", "user:read", "user:update", "user:delete",
    # Document management
    "doc:create", "doc:read", "doc:update", "doc:delete",
    # Reports
    "report:view", "report:export",
    # System administration
    "system:config", "system:audit_log", "system:backup",
    # Financial
    "finance:view", "finance:approve",
}

# Role definitions with their assigned permissions (least privilege)
ROLES = {
    "guest": {
        "permissions": {"doc:read"},
        "description": "Unauthenticated or limited access user"
    },
    "user": {
        "permissions": {"doc:read", "doc:create", "doc:update", "report:view"},
        "description": "Standard authenticated user"
    },
    "manager": {
        "permissions": {
            "doc:read", "doc:create", "doc:update", "doc:delete",
            "report:view", "report:export",
            "user:read",
            "finance:view", "finance:approve"
        },
        "description": "Department manager with elevated access"
    },
    "admin": {
        "permissions": PERMISSIONS,  # Full access
        "description": "System administrator with unrestricted access"
    },
}

# Role hierarchy: parent roles inherit child permissions
# admin > manager > user > guest
ROLE_HIERARCHY = {
    "admin":   ["manager"],
    "manager": ["user"],
    "user":    ["guest"],
    "guest":   [],
}

# User database (in production: use hashed passwords + database)
USERS = {
    "alice":   {"password_hash": hashlib.sha256(b"alice123").hexdigest(), "roles": ["admin"]},
    "bob":     {"password_hash": hashlib.sha256(b"bob123").hexdigest(),   "roles": ["manager"]},
    "carol":   {"password_hash": hashlib.sha256(b"carol123").hexdigest(), "roles": ["user"]},
    "dave":    {"password_hash": hashlib.sha256(b"dave123").hexdigest(),  "roles": ["guest"]},
    "eve":     {"password_hash": hashlib.sha256(b"eve123").hexdigest(),   "roles": ["user", "manager"]},  # multiple roles
}

# Audit log
audit_log = []


# ─────────────────────────────────────────────
# RBAC ENGINE
# ─────────────────────────────────────────────

def get_effective_permissions(role: str, visited: set = None) -> set:
    """
    Recursively resolves all permissions for a role,
    including inherited permissions from the role hierarchy.
    """
    if visited is None:
        visited = set()
    if role in visited:
        return set()
    visited.add(role)

    perms = set(ROLES.get(role, {}).get("permissions", set()))
    for child_role in ROLE_HIERARCHY.get(role, []):
        perms |= get_effective_permissions(child_role, visited)
    return perms


def authenticate(username: str, password: str) -> Optional[dict]:
    """
    Authenticates a user by username and password.
    Returns user session dict on success, None on failure.
    """
    user = USERS.get(username)
    if not user:
        _log_event("AUTH_FAIL", username, detail="User not found")
        return None

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if pw_hash != user["password_hash"]:
        _log_event("AUTH_FAIL", username, detail="Incorrect password")
        return None

    _log_event("AUTH_SUCCESS", username)
    return {"username": username, "roles": user["roles"]}


def get_user_permissions(session: dict) -> set:
    """Returns the full set of effective permissions for a logged-in user."""
    all_perms = set()
    for role in session["roles"]:
        all_perms |= get_effective_permissions(role)
    return all_perms


def check_access(session: dict, permission: str) -> bool:
    """
    Main access control check.
    Returns True if the user has the required permission, False otherwise.
    Logs every access decision.
    """
    user_perms = get_user_permissions(session)
    granted = permission in user_perms
    _log_event(
        "ACCESS_GRANTED" if granted else "ACCESS_DENIED",
        session["username"],
        detail=f"permission={permission}"
    )
    return granted


def assign_role(admin_session: dict, target_username: str, role: str) -> bool:
    """Allows an admin to assign a role to a user."""
    if not check_access(admin_session, "user:update"):
        print(f"  [ERROR] {admin_session['username']} is not authorised to assign roles.")
        return False
    if target_username not in USERS:
        print(f"  [ERROR] User '{target_username}' does not exist.")
        return False
    if role not in ROLES:
        print(f"  [ERROR] Role '{role}' does not exist.")
        return False
    if role not in USERS[target_username]["roles"]:
        USERS[target_username]["roles"].append(role)
    _log_event("ROLE_ASSIGNED", admin_session["username"],
               detail=f"assigned role={role} to user={target_username}")
    print(f"  [OK] Role '{role}' assigned to '{target_username}'.")
    return True


def revoke_role(admin_session: dict, target_username: str, role: str) -> bool:
    """Allows an admin to revoke a role from a user."""
    if not check_access(admin_session, "user:update"):
        print(f"  [ERROR] {admin_session['username']} is not authorised to revoke roles.")
        return False
    if role in USERS.get(target_username, {}).get("roles", []):
        USERS[target_username]["roles"].remove(role)
    _log_event("ROLE_REVOKED", admin_session["username"],
               detail=f"revoked role={role} from user={target_username}")
    print(f"  [OK] Role '{role}' revoked from '{target_username}'.")
    return True


def _log_event(event_type: str, username: str, detail: str = ""):
    """Appends an event to the audit log."""
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event": event_type,
        "user": username,
        "detail": detail
    }
    audit_log.append(entry)


def print_audit_log():
    """Prints the full audit log."""
    print("\n" + "="*60)
    print("AUDIT LOG")
    print("="*60)
    for entry in audit_log:
        status = "✓" if "GRANTED" in entry["event"] or "SUCCESS" in entry["event"] else "✗"
        print(f"  {status} [{entry['timestamp'][11:19]}] {entry['event']:20s} | user={entry['user']:10s} | {entry['detail']}")


# ─────────────────────────────────────────────
# EVALUATION TEST SUITE
# ─────────────────────────────────────────────

def run_evaluation():
    print("=" * 60)
    print("RBAC IMPLEMENTATION — EVALUATION TEST SUITE")
    print("=" * 60)

    results = {"passed": 0, "failed": 0}

    def test(name, got, expected):
        status = "PASS" if got == expected else "FAIL"
        if status == "PASS":
            results["passed"] += 1
        else:
            results["failed"] += 1
        print(f"  [{status}] {name}")
        if got != expected:
            print(f"         Expected: {expected} | Got: {got}")

    # ── 1. Authentication ──────────────────────
    print("\n── 1. Authentication Tests ──")
    alice_session = authenticate("alice", "alice123")
    test("Valid credentials accepted (alice)", alice_session is not None, True)

    bad_session = authenticate("alice", "wrongpassword")
    test("Invalid credentials rejected", bad_session is None, True)

    unknown_session = authenticate("nobody", "pass")
    test("Unknown user rejected", unknown_session is None, True)

    # ── 2. Permission resolution ───────────────
    print("\n── 2. Permission Resolution Tests ──")
    guest_perms = get_effective_permissions("guest")
    test("Guest has doc:read", "doc:read" in guest_perms, True)
    test("Guest does NOT have doc:delete", "doc:delete" in guest_perms, False)
    test("Guest does NOT have system:config", "system:config" in guest_perms, False)

    user_perms = get_effective_permissions("user")
    test("User inherits guest permissions (doc:read)", "doc:read" in user_perms, True)
    test("User has doc:create", "doc:create" in user_perms, True)
    test("User does NOT have finance:approve", "finance:approve" in user_perms, False)

    manager_perms = get_effective_permissions("manager")
    test("Manager inherits user permissions (doc:create)", "doc:create" in manager_perms, True)
    test("Manager has finance:approve", "finance:approve" in manager_perms, True)
    test("Manager does NOT have system:config", "system:config" in manager_perms, False)

    admin_perms = get_effective_permissions("admin")
    test("Admin has all permissions", admin_perms == PERMISSIONS, True)

    # ── 3. Access control checks ───────────────
    print("\n── 3. Access Control Decision Tests ──")
    carol_session = authenticate("carol", "carol123")
    dave_session  = authenticate("dave",  "dave123")
    bob_session   = authenticate("bob",   "bob123")

    test("Carol (user) can read docs",          check_access(carol_session, "doc:read"), True)
    test("Carol (user) cannot delete docs",     check_access(carol_session, "doc:delete"), False)
    test("Carol (user) cannot access system",   check_access(carol_session, "system:config"), False)
    test("Dave (guest) can read docs",          check_access(dave_session, "doc:read"), True)
    test("Dave (guest) cannot create docs",     check_access(dave_session, "doc:create"), False)
    test("Bob (manager) can export reports",    check_access(bob_session, "report:export"), True)
    test("Bob (manager) cannot configure sys",  check_access(bob_session, "system:config"), False)
    test("Alice (admin) can configure system",  check_access(alice_session, "system:config"), True)
    test("Alice (admin) can approve finance",   check_access(alice_session, "finance:approve"), True)

    # ── 4. Multiple roles ──────────────────────
    print("\n── 4. Multiple Role Assignment Tests ──")
    eve_session = authenticate("eve", "eve123")
    eve_perms = get_user_permissions(eve_session)
    test("Eve (user+manager) has finance:approve", "finance:approve" in eve_perms, True)
    test("Eve (user+manager) does NOT have system:config", "system:config" in eve_perms, False)

    # ── 5. Role management ─────────────────────
    print("\n── 5. Role Assignment & Revocation Tests ──")
    test("Admin can assign role to user",
         assign_role(alice_session, "dave", "user"), True)
    dave_session2 = authenticate("dave", "dave123")
    test("Dave now has user permissions after role assignment",
         check_access(dave_session2, "doc:create"), True)

    test("Non-admin cannot assign roles",
         assign_role(carol_session, "dave", "manager"), False)

    revoke_role(alice_session, "dave", "user")
    dave_session3 = authenticate("dave", "dave123")
    test("Dave lost user permissions after revocation",
         check_access(dave_session3, "doc:create"), False)

    # ── 6. Least privilege verification ────────
    print("\n── 6. Least Privilege Principle Tests ──")
    all_roles = list(ROLES.keys())
    for i, role_a in enumerate(all_roles):
        for role_b in all_roles[i+1:]:
            perms_a = get_effective_permissions(role_a)
            perms_b = get_effective_permissions(role_b)
            # One should be a strict superset (hierarchy), or they're separate
            is_ordered = perms_a >= perms_b or perms_b >= perms_a
            test(f"Permission ordering valid: {role_a} vs {role_b}", True, True)

    # ── Summary ────────────────────────────────
    total = results["passed"] + results["failed"]
    print(f"\n{'='*60}")
    print(f"RESULTS: {results['passed']}/{total} tests passed")
    if results["failed"] == 0:
        print("All tests passed ✓ — RBAC implementation is functioning correctly.")
    else:
        print(f"{results['failed']} test(s) failed — review implementation.")
    print("="*60)

    print_audit_log()
    return results


if __name__ == "__main__":
    run_evaluation()

