#! Elevator dispatcher — untrusted a call can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires dispatchCar — the elevator dispatcher sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant dispatchCar

type Floor = Lobby | Mezzanine | Roof
type Decision = GoTo(Floor) | HoldCar

let raw = fetch<web>  # UNTRUSTED a call — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { dispatchCar(d) }  # act on the trusted decision only
