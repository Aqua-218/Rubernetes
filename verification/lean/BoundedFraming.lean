import Lean

/-
  Bounded framing (spec/verification/formal-methods.md 7.3, "bounded framing").

  Theorem: after the length check, the allocation is at most the bound.
  If it were false, a malicious peer could announce a huge frame and exhaust
  host memory before the payload was ever read.

  The model mirrors lib/rubernetes/consensus/transport.rb Framing.read:
  the 4-byte length prefix is decoded, compared with `maxBytes`, and only
  then requests up to the announced payload length. This bound covers the
  payload bytes, excluding the fixed header and the IO/runtime allocator.
-/

namespace Rubernetes.Verification.Framing

/-- Result of reading a frame header. -/
inductive Decision where
  | reject
  | allocate (bytes : Nat)
deriving DecidableEq, Repr

/-- The decision procedure used by the transport. -/
def decide (maxBytes length : Nat) : Decision :=
  if length ≤ maxBytes then Decision.allocate length else Decision.reject

/-- The vsock decoder additionally rejects empty payloads. -/
def decideVsock (maxBytes length : Nat) : Decision :=
  if length = 0 then Decision.reject else decide maxBytes length

theorem vsock_allocation_le_bound (maxBytes length bytes : Nat)
    (h : decideVsock maxBytes length = Decision.allocate bytes) : bytes ≤ maxBytes := by
  unfold decideVsock at h
  split at h
  · contradiction
  · unfold decide at h
    split at h
    · cases h; assumption
    · contradiction

/-- Read at most the remaining bytes. Ruby IO must respect the requested
count when reporting a partial read. -/
theorem chunk_preserves_payload_bound (announced received chunk : Nat)
    (receivedWithin : received ≤ announced)
    (chunkWithin : chunk ≤ announced - received) :
    received + chunk ≤ announced := by omega

/-- Whatever the announced length, an allocation never exceeds the bound. -/
theorem allocation_le_bound (maxBytes length bytes : Nat)
    (h : decide maxBytes length = Decision.allocate bytes) : bytes ≤ maxBytes := by
  unfold decide at h
  split at h
  · cases h; assumption
  · cases h

/-- An announced length above the bound is always rejected (no allocation). -/
theorem reject_of_gt (maxBytes length : Nat) (h : maxBytes < length) :
    decide maxBytes length = Decision.reject := by
  unfold decide
  have : ¬ length ≤ maxBytes := Nat.not_le.mpr h
  simp [this]

/-- The allocation, when it happens, is exactly the announced length, so the
    peer cannot make the receiver allocate more than it announced either. -/
theorem allocate_exact (maxBytes length bytes : Nat)
    (h : decide maxBytes length = Decision.allocate bytes) : bytes = length := by
  unfold decide at h
  split at h
  · cases h; rfl
  · cases h

/-- The total memory held by a connection with at most `inflight` frames is bounded. -/
theorem total_le (maxBytes inflight : Nat) (sizes : List Nat)
    (hlen : sizes.length ≤ inflight) (hb : ∀ s ∈ sizes, s ≤ maxBytes) :
    sizes.sum ≤ inflight * maxBytes := by
  induction sizes generalizing inflight with
  | nil => simp
  | cons s rest ih =>
    simp only [List.sum_cons, List.length_cons] at *
    cases inflight with
    | zero => omega
    | succ n =>
      have hs : s ≤ maxBytes := hb s (List.mem_cons_self s rest)
      have hr : rest.sum ≤ n * maxBytes := ih n (by omega) (fun x hx => hb x (List.mem_cons_of_mem s hx))
      calc s + rest.sum ≤ maxBytes + n * maxBytes := Nat.add_le_add hs hr
        _ = (n + 1) * maxBytes := by rw [Nat.succ_mul, Nat.add_comm]

end Rubernetes.Verification.Framing

open Lean Rubernetes.Verification.Framing

private def runCase (input : Json) : Except String (Option Nat) := do
  let protocol ← input.getObjValAs? String "protocol"
  let bound ← input.getObjValAs? Nat "bound"
  let length ← input.getObjValAs? Nat "length"
  let decision ← match protocol with
    | "raft" => pure (decide bound length)
    | "vsock" => pure (decideVsock bound length)
    | _ => throw s!"unknown protocol: {protocol}"
  return match decision with
    | .reject => none
    | .allocate n => some n

def main : IO Unit := do
  let stdin ← IO.getStdin
  let input ← stdin.getLine
  let result := do
    let cases ← (← Json.parse input).getArr?
    cases.mapM runCase
  match result with
  | .ok cases => IO.println (toJson cases).compress
  | .error message => throw (IO.userError message)
