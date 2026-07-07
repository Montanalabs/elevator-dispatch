#! VULNERABLE elevator-dispatch — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant dispatchCar

let raw = fetch<web>
privileged { dispatchCar(raw) }  # tainted -> tool: REJECTED
