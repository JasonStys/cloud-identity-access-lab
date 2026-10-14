# Jason Stys: authoritative tenant/action/MFA and time-limited emergency grants in real Rego.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# rule: valid — line 31
# binding: permitted — line 45
# rule: permitted — line 45
# rule: permitted — line 47
# binding: principal — line 49
# binding: resource — line 50
# parameter: principal — line 60
# rule: identity_assurance — line 60
# parameter: principal — line 65
# rule: identity_assurance — line 65
# parameter: principal — line 70
# rule: identity_assurance — line 70
# rule: emergency_assurance — line 76
# rule: emergency_assurance — line 78
# binding: grant — line 80
# binding: item — line 89
# binding: decision — line 94
# rule: decision — line 94
# binding: reason — line 95
# rule: reason — line 95
# binding: reason — line 96
# rule: reason — line 96
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
