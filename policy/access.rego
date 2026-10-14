# Jason Stys: authoritative tenant/action/MFA and time-limited emergency grants in real Rego.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# rule: valid — line 30
# binding: permitted — line 44
# rule: permitted — line 46
# binding: principal — line 48
# rule: principal — line 48
# binding: resource — line 49
# rule: resource — line 49
# rule: identity_assurance — line 59
# rule: identity_assurance — line 64
# rule: identity_assurance — line 69
# rule: emergency_assurance — line 75
# rule: emergency_assurance — line 77
# binding: grant — line 79
# rule: grant — line 79
# binding: item — line 88
# binding: decision — line 93
# rule: decision — line 93
# binding: reason — line 94
# rule: reason — line 94
# binding: reason — line 95
# rule: reason — line 95
# END CODE MAP
package cial

import rego.v1

# Reject unknown or malformed context; caller roles/tenants are never authoritative.
valid if {
	is_object(input)
	object.keys(input) == {"subject", "mfa_fresh", "now", "action", "resource"}
	is_string(input.subject)
	is_boolean(input.mfa_fresh)
	is_number(input.now)
	input.now >= 0
	input.now == floor(input.now)
	data.lab.principals[input.subject]
	data.lab.resources[input.resource]
	input.action in {"read", "publish", "delete", "rotate"}
}

# Default deny includes explicit delete denial and both identity/resource permission ceilings.
default permitted := false

permitted if {
	valid
	principal := data.lab.principals[input.subject]
	resource := data.lab.resources[input.resource]
	principal.tenant == resource.tenant
	input.action in principal.actions
	input.action in resource.actions
	input.action != "delete"
	identity_assurance(principal)
	emergency_assurance
}

# Human writes require a fresh issuer-attested MFA claim. Workloads have a separate closed subject registry.
identity_assurance(principal) if {
	principal.kind == "workload"
	input.action == "publish"
}

identity_assurance(principal) if {
	principal.kind == "human"
	input.action == "read"
}

identity_assurance(principal) if {
	principal.kind == "human"
	input.mfa_fresh
}

# Ordinary actions do not acquire emergency privilege; rotate requires two independent trusted approvers.
emergency_assurance if input.action != "rotate"

emergency_assurance if {
	input.action == "rotate"
	grant := data.lab.emergency
	grant.subject == input.subject
	grant.action == input.action
	grant.resource == input.resource
	grant.starts <= input.now
	input.now < grant.expires
	grant.expires - grant.starts <= 900
	grant.expires > grant.starts
	count(grant.approvers) == 2
	count({item | some item in grant.approvers}) == 2
	not input.subject in grant.approvers
}

# The stable decision never contains tokens, signing keys or raw claims.
decision := {"allow": permitted, "reason": reason}
reason := "allowed" if permitted
reason := "policy_denied" if not permitted
