# opa eval --data policy.rego --input ./.github/workflows/*.yml "data.main.deny"

package main

# Return an error message if the workflow does not use actions/checkout@v2
deny[msg] {
    not uses_checkout_v2
    msg = "The workflow does not use actions/checkout@v2. It is recommended to use this action"
}

# Helper rule to check if the workflow uses actions/checkout@v2
uses_checkout_v2 {
    step := input.jobs[_].steps[_]
    step.uses == "actions/checkout@v2"
}
