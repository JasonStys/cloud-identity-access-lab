# Jason Stys: native Terraform plan-only document assertions, no provider or remote resources.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# run: exact_trust_and_least_privilege — line 30
# configuration: command — line 31
# configuration: condition — line 33
# configuration: error_message — line 34
# configuration: condition — line 37
# configuration: error_message — line 38
# configuration: condition — line 41
# configuration: error_message — line 42
# configuration: condition — line 45
# configuration: error_message — line 46
# run: reject_wildcard_subject — line 49
# configuration: command — line 50
# configuration: expect_failures — line 52
# run: reject_legacy_ambiguous_subject — line 54
# configuration: command — line 55
# configuration: expect_failures — line 57
# run: reject_account_injection — line 59
# configuration: command — line 60
# configuration: expect_failures — line 62
# run: reject_bucket_path — line 64
# configuration: command — line 65
# configuration: expect_failures — line 67
# run: different_exact_branch — line 69
# configuration: command — line 70
# configuration: condition — line 73
# configuration: error_message — line 74
# END CODE MAP
run "exact_trust_and_least_privilege" {
  command = plan
  assert {
    condition     = output.trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "Trust audience must be the exact AWS STS audience."
  }
  assert {
    condition     = output.trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == var.subject && length(output.trust.Statement) == 1
    error_message = "Trust must pin one exact subject, without alternate allow paths."
  }
  assert {
    condition     = output.identity.Statement[0].Action == ["s3:PutObject"] && output.identity.Statement[0].Resource == "arn:aws:s3:::synthetic-alpha-artifacts/releases/*"
    error_message = "Release identity must not expand to read/delete/other prefixes."
  }
  assert {
    condition     = output.boundary.Statement[1].Effect == "Deny" && output.boundary.Statement[1].Action == ["s3:DeleteObject"]
    error_message = "Delete must remain explicitly denied in the example boundary."
  }
}
run "reject_wildcard_subject" {
  command = plan
  variables { subject = "repo:synthetic-org@101/synthetic-release@202:*" }
  expect_failures = [var.subject]
}
run "reject_legacy_ambiguous_subject" {
  command = plan
  variables { subject = "repo:synthetic-org/synthetic-release:ref:refs/heads/main" }
  expect_failures = [var.subject]
}
run "reject_account_injection" {
  command = plan
  variables { account_id = "*" }
  expect_failures = [var.account_id]
}
run "reject_bucket_path" {
  command = plan
  variables { bucket = "synthetic-alpha-artifacts/private/*" }
  expect_failures = [var.bucket]
}
run "different_exact_branch" {
  command = plan
  variables { subject = "repo:synthetic-org@101/synthetic-release@202:ref:refs/heads/release" }
  assert {
    condition     = output.trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:synthetic-org@101/synthetic-release@202:ref:refs/heads/release"
    error_message = "Configured branch must be preserved exactly."
  }
}
