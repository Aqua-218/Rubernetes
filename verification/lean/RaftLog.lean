import Lean

/-!
Raft log operations (spec/verification/formal-methods.md §7.3).
If matching terms could leave different prefixes after successful
replication, replicas could apply different commands at the same index.

This models an uncompacted follower processing a contiguous AppendEntries
batch: keep entries until the first conflicting term, reject a conflict
within the committed prefix, replace the conflicting suffix, and retain a
local suffix when an incoming batch ends before any conflict.
-/

namespace Rubernetes.Verification.Raft

structure Entry where
  term : Nat
  value : Nat
deriving DecidableEq, Repr, Lean.FromJson, Lean.ToJson

abbrev Log := List Entry

def LogMatching (a b : Log) : Prop :=
  ∀ n, n < a.length → n < b.length → (a[n]?).map Entry.term = (b[n]?).map Entry.term →
    a.take (n + 1) = b.take (n + 1)

def reconcile (committed : Nat) : Log → Log → Option Log
  | follower, [] => some follower
  | [], incoming => some incoming
  | existing :: follower, sent :: incoming =>
    if existing.term = sent.term then
      (reconcile (committed - 1) follower incoming).map (existing :: ·)
    else if committed = 0 then some (sent :: incoming) else none

def anchorMatches (log : Log) (index term : Nat) : Bool :=
  if index = 0 then true else (log[index - 1]?.map Entry.term) == some term

def appendEntries (follower : Log) (committed prevIndex prevTerm : Nat) (entries : Log) : Option Log :=
  if anchorMatches follower prevIndex prevTerm then
    (reconcile (committed - prevIndex) (follower.drop prevIndex) entries).map (follower.take prevIndex ++ ·)
  else none

/-- Matching anchor terms justify the prefix comparison only when the
LogMatching invariant initially holds for the two replicas. -/
theorem accepted_anchor_prefix (follower leader : Log) (index term : Nat)
    (prior : LogMatching follower leader)
    (followerAnchor : anchorMatches follower index term = true)
    (leaderAnchor : anchorMatches leader index term = true) :
    follower.take index = leader.take index := by
  cases index with
  | zero => simp
  | succ n =>
    have hf : (follower[n]?).map Entry.term = some term := by simpa [anchorMatches] using followerAnchor
    have hl : (leader[n]?).map Entry.term = some term := by simpa [anchorMatches] using leaderAnchor
    have fbound : n < follower.length := by
      by_cases h : n < follower.length
      · exact h
      · simp [List.getElem?_eq_none (Nat.le_of_not_lt h)] at hf
    have lbound : n < leader.length := by
      by_cases h : n < leader.length
      · exact h
      · simp [List.getElem?_eq_none (Nat.le_of_not_lt h)] at hl
    exact prior n fbound lbound (hf.trans hl.symm)

/-- LogMatching of complete logs entails LogMatching after removing their
heads. This permits following the batch's matching terms one at a time. -/
private theorem matching_tails (existing sent : Entry) (follower incoming : Log)
    (prior : LogMatching (existing :: follower) (sent :: incoming)) :
    LogMatching follower incoming := by
  intro n hf hl equalTerm
  have whole := prior (n + 1) (by simpa using hf) (by simpa using hl) (by simpa using equalTerm)
  exact (List.cons.inj (by simpa using whole)).2

theorem reconciled_batch_matches (committed : Nat) (follower incoming result : Log)
    (prior : LogMatching follower incoming)
    (accepted : reconcile committed follower incoming = some result) :
    result.take incoming.length = incoming := by
  induction follower generalizing committed incoming result with
  | nil =>
    cases incoming <;> simp [reconcile] at accepted <;> simp [← accepted]
  | cons existing follower ih =>
    cases incoming with
    | nil => simp
    | cons sent incoming =>
      by_cases same : existing.term = sent.term
      · have entry : existing = sent := by
          simpa using prior 0 (by simp) (by simp) (by simpa using same)
        cases tail : reconcile (committed - 1) follower incoming with
        | none => simp [reconcile, same, tail] at accepted
        | some next =>
          have merged : next.take incoming.length = incoming :=
            ih _ _ _ (matching_tails existing sent follower incoming prior) tail
          have value : existing :: next = result := by simpa [reconcile, same, tail] using accepted
          simp [← value, entry, merged]
      · by_cases noneCommitted : committed = 0 <;> simp_all [reconcile]

theorem committed_batch_prefix_preserved (committed : Nat) (follower incoming result : Log)
    (valid : committed ≤ follower.length)
    (accepted : reconcile committed follower incoming = some result) :
    result.take committed = follower.take committed := by
  induction follower generalizing committed incoming result with
  | nil => have h : committed = 0 := by simpa using valid
           simp [h]
  | cons existing follower ih =>
    cases committed with
    | zero => simp
    | succ n =>
      cases incoming with
      | nil => simpa [reconcile] using congrArg (fun x => x.map (List.take (n + 1))) accepted.symm
      | cons sent incoming =>
        by_cases same : existing.term = sent.term
        · cases tail : reconcile n follower incoming with
          | none => simp [reconcile, same, tail] at accepted
          | some next =>
            have value : existing :: next = result := by simpa [reconcile, same, tail] using accepted
            simp [← value, ih n incoming next (by simpa using valid) tail]
        · simp [reconcile, same] at accepted

private theorem matching_drop (count : Nat) (follower leader : Log) (prior : LogMatching follower leader) :
    LogMatching (follower.drop count) (leader.drop count) := by
  induction count generalizing follower leader with
  | zero => exact prior
  | succ n ih =>
    cases follower with
    | nil => intro _ bound; simp at bound
    | cons f fs =>
      cases leader with
      | nil => intro _ _ bound; simp at bound
      | cons l ls => exact ih fs ls (matching_tails f l fs ls prior)

private theorem matching_take_right (count : Nat) (follower leader : Log) (prior : LogMatching follower leader) :
    LogMatching follower (leader.take count) := by
  intro n hf hl equalTerm
  have bounds : n < count ∧ n < leader.length := by
    simpa [List.length_take, Nat.lt_min] using hl
  rw [List.getElem?_take, if_pos bounds.1] at equalTerm
  rw [List.take_take, Nat.min_eq_left (by omega : n + 1 ≤ count)]
  exact prior n hf bounds.2 equalTerm

private theorem anchor_index_le_length (log : Log) (index term : Nat)
    (accepted : anchorMatches log index term = true) : index ≤ log.length := by
  by_cases bound : index ≤ log.length
  · exact bound
  · have positive : index ≠ 0 := by omega
    have missing : log[index - 1]? = none := List.getElem?_eq_none (by omega)
    simp [anchorMatches, positive, missing] at accepted

/-- A longer result means no incoming term conflicted, so we kept the
follower's existing entries, including its complete trailing suffix. -/
private theorem reconcile_keeps_longer_log (committed : Nat) (follower incoming result : Log)
    (accepted : reconcile committed follower incoming = some result)
    (longer : incoming.length < result.length) : result = follower := by
  induction follower generalizing committed incoming result with
  | nil => cases incoming <;> simp_all [reconcile]
  | cons existing follower ih =>
    cases incoming with
    | nil => simpa [reconcile] using accepted.symm
    | cons sent incoming =>
      by_cases same : existing.term = sent.term
      · cases tail : reconcile (committed - 1) follower incoming with
        | none => simp [reconcile, same, tail] at accepted
        | some next =>
          have value : existing :: next = result := by simpa [reconcile, same, tail] using accepted
          subst result
          simp [ih _ _ _ tail (by simpa using longer)]
      · by_cases noneCommitted : committed = 0 <;> simp_all [reconcile]

/-- LogMatching is preserved for an accepted contiguous batch covering any
portion of the leader's suffix. The proof includes heartbeats (empty batches)
and retained follower entries beyond the end of the batch. -/
theorem logMatching_after_append (follower leader result : Log) (committed prev term count : Nat)
    (prior : LogMatching follower leader)
    (leaderAnchor : anchorMatches leader prev term = true)
    (accepted : appendEntries follower committed prev term ((leader.drop prev).take count) = some result) :
    LogMatching result leader := by
  unfold appendEntries at accepted
  split at accepted
  · rename_i followerAnchor
    let entries := (leader.drop prev).take count
    change (reconcile (committed - prev) (follower.drop prev) entries).map (follower.take prev ++ ·) = some result at accepted
    cases hmerge : reconcile (committed - prev) (follower.drop prev) entries with
    | none => simp [hmerge] at accepted
    | some merged =>
      have res : follower.take prev ++ merged = result := by simpa [hmerge] using accepted
      have sharedPrefix : follower.take prev = leader.take prev :=
        accepted_anchor_prefix _ _ _ _ prior followerAnchor leaderAnchor
      have fLen : (follower.take prev).length = prev := by
        simp [List.length_take, Nat.min_eq_left (anchor_index_le_length _ _ _ followerAnchor)]
      have lLen : (leader.take prev).length = prev := by rw [← sharedPrefix, fLen]
      intro n resultBound leaderBound sameTerm
      by_cases covered : n < prev + entries.length
      · have suffixMatching := matching_take_right count _ _ (matching_drop prev follower leader prior)
        have mergedPrefix : merged.take entries.length = entries :=
          reconciled_batch_matches _ _ _ _ suffixMatching hmerge
        have entriesLength : entries.length ≤ count := by
          rw [show entries.length = min count (leader.drop prev).length from List.length_take _ _]
          exact Nat.min_le_left _ _
        have includesEntries : (leader.drop prev).take entries.length = entries := by
          have allEntries : entries.take entries.length = entries := List.take_length entries
          change ((leader.drop prev).take count).take entries.length = entries at allEntries
          simpa only [List.take_take, Nat.min_eq_left entriesLength] using allEntries
        have resultPrefix : result.take (prev + entries.length) = leader.take (prev + entries.length) := by
          calc
            result.take (prev + entries.length) = follower.take prev ++ entries := by
              have splitFollower := List.take_append (l₁ := follower.take prev) (l₂ := merged) entries.length
              simpa only [fLen, res, mergedPrefix] using splitFollower
            _ = leader.take (prev + entries.length) := by
              have splitLeader := List.take_append (l₁ := leader.take prev) (l₂ := leader.drop prev) entries.length
              simpa only [lLen, List.take_append_drop, includesEntries, sharedPrefix] using splitLeader.symm
        have shorter := congrArg (List.take (n + 1)) resultPrefix
        simpa only [List.take_take, Nat.min_eq_left (by omega : n + 1 ≤ prev + entries.length)] using shorter
      · have longer : entries.length < merged.length := by
          rw [← res, List.length_append, fLen] at resultBound
          omega
        have sameFollower := reconcile_keeps_longer_log _ _ _ _ hmerge longer
        have sameLog : result = follower := by rw [← res, sameFollower, List.take_append_drop]
        rw [sameLog] at resultBound sameTerm ⊢
        exact prior n resultBound leaderBound sameTerm
  · simp at accepted

/-- A successful append leaves every committed entry unchanged, including
entries covered by the incoming batch after its anchor. -/
theorem committed_prefix_preserved (follower entries result : Log) (committed prev term : Nat)
    (valid : committed ≤ follower.length)
    (accepted : appendEntries follower committed prev term entries = some result) :
    result.take committed = follower.take committed := by
  unfold appendEntries at accepted
  split at accepted
  · rename_i followerAnchor
    cases merged : reconcile (committed - prev) (follower.drop prev) entries with
    | none => simp [merged] at accepted
    | some next =>
      have resultEq : follower.take prev ++ next = result := by simpa [merged] using accepted
      have len : (follower.take prev).length = prev := by
        simp [List.length_take, Nat.min_eq_left (anchor_index_le_length _ _ _ followerAnchor)]
      by_cases anchored : committed ≤ prev
      · rw [← resultEq, List.take_append_of_le_length (by simpa only [len] using anchored),
            List.take_take, Nat.min_eq_left anchored]
      · have bound : committed - prev ≤ (follower.drop prev).length := by simp [List.length_drop]; omega
        have preserved := committed_batch_prefix_preserved _ _ _ _ bound merged
        have nextSplit := List.take_append (l₁ := follower.take prev) (l₂ := next) (committed - prev)
        have originalSplit := List.take_append (l₁ := follower.take prev) (l₂ := follower.drop prev) (committed - prev)
        have size : prev + (committed - prev) = committed := by omega
        rw [preserved] at nextSplit
        simpa only [len, size, resultEq, List.take_append_drop] using nextSplit.trans originalSplit.symm
  · simp at accepted

end Rubernetes.Verification.Raft

open Lean Rubernetes.Verification.Raft

private def runCase (input : Json) : Except String (Option Log) := do
  let follower ← input.getObjValAs? Log "follower"
  let committed ← input.getObjValAs? Nat "committed"
  let index ← input.getObjValAs? Nat "prev_index"
  let term ← input.getObjValAs? Nat "prev_term"
  let entries ← input.getObjValAs? Log "entries"
  return appendEntries follower committed index term entries

def main : IO Unit := do
  let stdin ← IO.getStdin
  let input ← stdin.getLine
  let result := do
    let cases ← (← Json.parse input).getArr?
    cases.mapM runCase
  match result with
  | .ok cases => IO.println (toJson cases).compress
  | .error message => throw (IO.userError message)
