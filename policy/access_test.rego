# Jason Stys: native Rego positive/negative and trusted-registry emergency boundary tests.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# binding: base — line 34
# rule: base — line 34
# rule: test_human_publish — line 35
# rule: test_no_mfa — line 36
# rule: test_read_without_mfa — line 37
# rule: test_cross_tenant — line 38
# rule: test_resource_ceiling — line 39
# rule: test_delete — line 40
# rule: test_unknown_subject — line 41
# rule: test_extra_claim — line 42
# rule: test_bad_time — line 43
# rule: test_unknown_resource — line 44
# rule: test_missing_field — line 45
# rule: test_workload_scope — line 46
# binding: emergency — line 50
# rule: emergency — line 50
# rule: test_emergency_start — line 51
# rule: test_emergency_before — line 52
# rule: test_emergency_expiry — line 53
# rule: test_emergency_mfa — line 54
# rule: test_approver_duplicate — line 55
# rule: test_approver_self — line 59
# rule: test_long_emergency — line 63
# rule: test_empty_input — line 67
# END CODE MAP
package cial_test

import data.cial
import rego.v1

# Inputs are synthetic verifier contexts, never raw token claims.
base := {"subject": "engineer-alpha", "mfa_fresh": true, "now": 2000000000, "action": "publish", "resource": "alpha-artifacts"}
test_human_publish if cial.decision.allow with input as base
test_no_mfa if not cial.decision.allow with input as object.union(base, {"mfa_fresh": false})
test_read_without_mfa if cial.decision.allow with input as object.union(base, {"mfa_fresh": false, "action": "read", "resource": "alpha-docs"})
test_cross_tenant if not cial.decision.allow with input as object.union(base, {"resource": "beta-docs", "action": "read"})
test_resource_ceiling if not cial.decision.allow with input as object.union(base, {"resource": "alpha-docs"})
test_delete if not cial.decision.allow with input as object.union(base, {"action": "delete"})
test_unknown_subject if not cial.decision.allow with input as object.union(base, {"subject": "admin"})
test_extra_claim if not cial.decision.allow with input as object.union(base, {"role": "admin"})
test_bad_time if not cial.decision.allow with input as object.union(base, {"now": -1})
test_unknown_resource if not cial.decision.allow with input as object.union(base, {"resource": "*"})
test_missing_field if not cial.decision.allow with input as object.remove(base, {"mfa_fresh"})
test_workload_scope if {
	not cial.decision.allow with input as object.union(base, {"subject": "repo:synthetic-org@101/synthetic-release@202:ref:refs/heads/main", "action": "read"})
}

emergency := object.union(base, {"subject": "responder-alpha", "action": "rotate", "resource": "alpha-keys"})
test_emergency_start if cial.decision.allow with input as emergency
test_emergency_before if not cial.decision.allow with input as object.union(emergency, {"now": 1999999999})
test_emergency_expiry if not cial.decision.allow with input as object.union(emergency, {"now": 2000000060})
test_emergency_mfa if not cial.decision.allow with input as object.union(emergency, {"mfa_fresh": false})
test_approver_duplicate if {
	not cial.decision.allow with input as emergency with data.lab.emergency as object.union(data.lab.emergency, {"approvers": ["approver-one", "approver-one"]})
}

test_approver_self if {
	not cial.decision.allow with input as emergency with data.lab.emergency as object.union(data.lab.emergency, {"approvers": ["responder-alpha", "approver-two"]})
}

test_long_emergency if {
	not cial.decision.allow with input as emergency with data.lab.emergency as object.union(data.lab.emergency, {"expires": 2000001000})
}

test_empty_input if not cial.decision.allow with input as {}
