import Lean

/-!
Pure runtime algorithms from spec/verification/formal-methods.md §7.3.
The executable interface at the end is used by the Ruby differential tests.
-/

namespace Rubernetes.Verification

namespace IPAM

/-- The ordered candidates and used addresses are scoped to one node and IP family.
A duplicate live allocation would prevent two Pods from communicating. -/
def firstFree (candidates used : List Nat) : Option Nat :=
  candidates.find? fun ip => !used.contains ip

theorem reservation_preserves_uniqueness (candidates used : List Nat) (ip : Nat)
    (unique : used.Nodup) (selected : firstFree candidates used = some ip) :
    (ip :: used).Nodup := by
  have free := List.find?_some selected
  exact List.nodup_cons.mpr ⟨by simpa [firstFree] using free, unique⟩

/-- IPAddr generates addresses as the cluster base plus an aligned node block
and a host offset. A bounded host offset recovers its unique node block. -/
theorem different_node_blocks_disjoint (base width i j a b : Nat)
    (ha : a < width) (hb : b < width) (distinct : i ≠ j) :
    base + i * width + a ≠ base + j * width + b := by
  intro same
  have blocks : i * width + a = j * width + b := by omega
  have hwidth : 0 < width := by omega
  have left : (i * width + a) / width = i := by
    rw [Nat.mul_comm i, Nat.mul_add_div hwidth, Nat.div_eq_of_lt ha, Nat.add_zero]
  have right : (j * width + b) / width = j := by
    rw [Nat.mul_comm j, Nat.mul_add_div hwidth, Nat.div_eq_of_lt hb, Nat.add_zero]
  exact distinct (left.symm.trans ((congrArg (· / width) blocks).trans right))

/-- A stale operation might still have a lease key after recovery. Releasing
the newer lease through that old key would let a third live Pod take the IP. -/
def releaseLease (owner : Option String) (operation : String) : Option String :=
  if owner = some operation then none else owner

theorem stale_release_preserves_current_owner (owner stale : String) (distinct : owner ≠ stale) :
    releaseLease (some owner) stale = some owner := by
  simp [releaseLease, distinct]

end IPAM

namespace Rollback

/-- The ledger's acquisition sequence is ascending. A plan uses the remaining
claims, in reverse order. Releasing a prerequisite first could destroy state
still held by a live dependent. -/
def plan (acquisition : List Nat) (released : List Nat) : List Nat :=
  (acquisition.filter fun sequence => !released.contains sequence).reverse

theorem plan_is_reverse_topological (acquisition released : List Nat)
    (forward : acquisition.Pairwise (· < ·)) :
    (plan acquisition released).Pairwise (· > ·) := by
  unfold plan
  exact List.pairwise_reverse.mpr (forward.filter _)

theorem plan_covers_remaining_resources (acquisition released : List Nat) (resource : Nat) :
    resource ∈ plan acquisition released ↔ resource ∈ acquisition ∧ resource ∉ released := by
  simp [plan, List.mem_reverse, List.mem_filter]

/-- Release only the prefix before a failed cleanup. The remaining resources
may include prerequisites still held by the failed resource. -/
def execute (acquisition released : List Nat) (firstFailure : Option Nat) : List Nat :=
  (plan acquisition released).takeWhile fun sequence => some sequence != firstFailure

theorem successful_cleanup_preserves_reverse_order (acquisition released : List Nat)
    (firstFailure : Option Nat) (forward : acquisition.Pairwise (· < ·)) :
    (execute acquisition released firstFailure).Pairwise (· > ·) := by
  exact List.Pairwise.sublist (List.takeWhile_sublist _) (plan_is_reverse_topological acquisition released forward)

theorem execution_stops_at_first_failure (acquisition released before after : List Nat) (failed : Nat)
    (position : plan acquisition released = before ++ failed :: after)
    (earlierSuccess : ∀ sequence ∈ before, sequence ≠ failed) :
    execute acquisition released (some failed) = before := by
  unfold execute
  rw [position]
  clear position
  induction before with
  | nil => simp [List.takeWhile]
  | cons head rest ih =>
    have succeeds : head ≠ failed := earlierSuccess head (by simp)
    have tailSucceeds := ih (fun sequence present => earlierSuccess sequence (List.mem_cons_of_mem _ present))
    simp [List.takeWhile, succeeds, tailSucceeds]

end Rollback

namespace Identity

/-- An identity value is tagged with its field name, matching IdentityLedger's
per-field index of seen values. Released identities remain in the index.
A repeated field would allow an old token, nonce or workspace to be reused. -/
abbrev TaggedValue := String × String

def issue (seen values : List TaggedValue) : Option (List TaggedValue) :=
  if values.any seen.contains then none else some (values ++ seen)

theorem issued_identity_disjoint (seen values next : List TaggedValue)
    (issued : issue seen values = some next) :
    ∀ value ∈ values, value ∉ seen := by
  unfold issue at issued
  split at issued
  · contradiction
  · intro value present previous
    rename_i fresh
    exact fresh (List.any_eq_true.mpr ⟨value, present, by simpa using previous⟩)

theorem issuance_retains_history (seen values next : List TaggedValue)
    (issued : issue seen values = some next) :
    ∀ value ∈ seen, value ∈ next := by
  unfold issue at issued
  split at issued
  · contradiction
  · cases issued
    intro value historic
    exact List.mem_append_right _ historic

end Identity

namespace Overlay

/-- At a single path, absence falls through and a tombstone hides lower layers.
An incorrect precedence would expose a file deleted or replaced by an upper
image layer. Directory ancestry and copy-up are kernel/OCI concerns. -/
inductive Edit (α : Type) where
  | absent
  | remove
  | put (value : α)

def over (upper lower : Edit α) : Edit α :=
  match upper with
  | .absent => lower
  | edit => edit

def compose (upper lower : String → Edit α) : String → Edit α :=
  fun path => over (upper path) (lower path)

theorem compose_assoc (upper middle lower : String → Edit α) :
    compose (compose upper middle) lower = compose upper (compose middle lower) := by
  funext path
  cases h : upper path <;> simp [compose, over, h]

theorem first_edit_wins (before after : List (Edit α)) (edit : Edit α)
    (transparent : ∀ e ∈ before, e = .absent)
    (terminal : edit ≠ .absent) :
    (before ++ edit :: after).foldr over .absent = edit := by
  induction before with
  | nil => cases edit <;> simp_all [over]
  | cons head rest ih =>
    rw [transparent head (by simp)]
    simpa [over] using ih fun e he => transparent e (List.mem_cons_of_mem _ he)

end Overlay

namespace Cgroup

/-- None is the cgroup v2 unbounded marker. The effective hard upper bound
includes each ancestor's local limit. Losing an ancestor cap would let a
container exceed the limit of its Pod or QoS group. -/
def restrict (parent child : Option Nat) : Option Nat :=
  match parent, child with
  | none, limit | limit, none => limit
  | some p, some c => some (min p c)

def effective (limits : List (Option Nat)) : Option Nat :=
  limits.foldl restrict none

theorem at_most_every_ancestor (limits : List (Option Nat)) (ancestor : Nat)
    (present : some ancestor ∈ limits) :
    ∃ bound, effective limits = some bound ∧ bound ≤ ancestor := by
  have step (remaining : List (Option Nat)) (parent n : Nat) :
      parent ≤ n → ∃ bound, remaining.foldl restrict (some parent) = some bound ∧ bound ≤ n := by
    induction remaining generalizing parent with
    | nil => exact fun h => ⟨parent, rfl, h⟩
    | cons next rest ih =>
      cases next with
      | none => exact ih parent
      | some c =>
        intro h
        exact ih (min parent c) (Nat.le_trans (Nat.min_le_left parent c) h)
  have all (limits : List (Option Nat)) (acc : Option Nat) :
      some ancestor ∈ limits → ∃ bound, limits.foldl restrict acc = some bound ∧ bound ≤ ancestor := by
    induction limits generalizing acc with
    | nil => simp
    | cons next rest ih =>
      intro h
      rcases List.mem_cons.mp h with same | inRest
      · subst next
        cases acc with
        | none => exact step rest ancestor ancestor (Nat.le_refl _)
        | some p => exact step rest (min p ancestor) ancestor (Nat.min_le_right p ancestor)
      · exact ih (restrict acc next) inRest
  exact all limits none present

end Cgroup

namespace Scheduler

/-- Filter stops at the first rejection or plugin error. A missing result
means a plugin failed to return a supported response. Skipping either kind
of failure could assign a Pod to a node that cannot run it. -/
inductive FilterResult where
  | accepted
  | rejected (plugin : Nat)
  | error (plugin : Nat)
deriving DecidableEq

def filter (ordinal : Nat) : List (Option Bool) → FilterResult
  | [] => .accepted
  | none :: _ => .error ordinal
  | some false :: _ => .rejected ordinal
  | some true :: rest => filter (ordinal + 1) rest

theorem filter_accepts_iff_all_approve (ordinal : Nat) (outputs : List (Option Bool)) :
    filter ordinal outputs = .accepted ↔ ∀ output ∈ outputs, output = some true := by
  induction outputs generalizing ordinal with
  | nil => simp [filter]
  | cons output rest ih =>
    cases output with
    | none => simp [filter]
    | some decision => cases decision <;> simp [filter, ih]

/-- Score gives valid output (0 through 100) its configured positive weight
and skips a disabled extension. An unstable sum would change node rankings
for the same plugin observations. -/
def score : List (Option Int × Nat) → Option Int
  | [] => some 0
  | (none, _) :: rest => score rest
  | (some value, weight) :: rest =>
    if 0 ≤ value ∧ value ≤ 100 then (score rest).map (value * Int.ofNat weight + ·) else none

inductive ScoreEvaluation : List (Option Int × Nat) → Int → Prop where
  | empty : ScoreEvaluation [] 0
  | skip (weight : Nat) (rest : ScoreEvaluation outputs total) :
    ScoreEvaluation ((none, weight) :: outputs) total
  | weighted (valid : 0 ≤ value ∧ value ≤ 100) (rest : ScoreEvaluation outputs total) :
    ScoreEvaluation ((some value, weight) :: outputs) (value * Int.ofNat weight + total)

theorem score_matches_evaluation (outputs : List (Option Int × Nat)) (total : Int)
    (evaluated : ScoreEvaluation outputs total) : score outputs = some total := by
  induction evaluated with
  | empty => simp [score]
  | skip _ _ ih => exact ih
  | weighted valid _ ih => simp [score, valid, ih]

theorem score_is_deterministic (outputs : List (Option Int × Nat)) (x y : Int)
    (first : ScoreEvaluation outputs x) (second : ScoreEvaluation outputs y) : x = y :=
  Option.some.inj ((score_matches_evaluation _ _ first).symm.trans (score_matches_evaluation _ _ second))

end Scheduler

end Rubernetes.Verification

open Lean Rubernetes.Verification

private def runCase (input : Json) : Except String Json := do
  match ← input.getObjValAs? String "kind" with
  | "ipam" =>
    let candidates ← input.getObjValAs? (List Nat) "candidates"
    let used ← input.getObjValAs? (List Nat) "used"
    return toJson (IPAM.firstFree candidates used)
  | "rollback" =>
    let acquisition ← input.getObjValAs? (List Nat) "acquisition"
    let released ← input.getObjValAs? (List Nat) "released"
    let firstFailure ← input.getObjValAs? (Option Nat) "first_failure"
    return toJson (Rollback.execute acquisition released firstFailure)
  | "identity" =>
    let seen ← input.getObjValAs? (List Identity.TaggedValue) "seen"
    let values ← input.getObjValAs? (List Identity.TaggedValue) "values"
    return toJson (Identity.issue seen values).isSome
  | "overlay" =>
    let codes ← input.getObjValAs? (List Nat) "edits"
    let edits := codes.map fun
      | 0 => Overlay.Edit.absent
      | 1 => Overlay.Edit.remove
      | n + 2 => Overlay.Edit.put n
    return toJson (match edits.foldr Overlay.over Overlay.Edit.absent with
      | .absent => 0
      | .remove => 1
      | .put value => value + 2)
  | "cgroup" =>
    let limits ← input.getObjValAs? (List (Option Nat)) "limits"
    return toJson (Cgroup.effective limits)
  | "scheduler_filter" =>
    let outputs ← input.getObjValAs? (List (Option Bool)) "outputs"
    return toJson (match Scheduler.filter 0 outputs with
      | .accepted => "accepted"
      | .rejected index => s!"rejected:{index}"
      | .error index => s!"error:{index}")
  | "scheduler_score" =>
    let outputs ← input.getObjValAs? (List (Option Int × Nat)) "outputs"
    return toJson (Scheduler.score outputs)
  | name => throw s!"unknown algorithm: {name}"

def main : IO Unit := do
  let stdin ← IO.getStdin
  let input ← stdin.getLine
  let result := do
    let cases ← (← Json.parse input).getArr?
    cases.mapM runCase
  match result with
  | .ok results => IO.println (Json.arr results).compress
  | .error message => throw (IO.userError message)
