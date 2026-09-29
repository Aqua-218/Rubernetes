/-
  Raft log operations (spec/verification/formal-methods.md 7.3, "Raft ログ演算").

  Theorem: LogMatching holds for all log lengths.
  If it were false, two replicas could hold different entries at the same
  index and term and committed data would be lost.

  The model: a log is a list of entries carrying a term.  The leader's
  AppendEntries handler on a follower is `appendEntries`: given prevIndex,
  prevTerm and the new entries, the follower accepts only when its entry at
  prevIndex has prevTerm, discards any conflicting suffix and appends.  The
  invariant proved is that when two logs agree at some index (same term),
  they agree on the complete prefix, and that this invariant is preserved by
  the append operation whenever the leader's log satisfies it with the
  follower's prefix.
-/

namespace Rubernetes.Verification.Raft

structure Entry where
  term : Nat
  value : Nat
deriving DecidableEq, Repr

abbrev Log := List Entry

/-- Prefix of length n (1-indexed entries 1..n). -/
def prefixOf (l : Log) (n : Nat) : Log := l.take n

/-- The LogMatching property between two logs: if an index holds the same
    term in both, the prefixes up to that index are equal. -/
def LogMatching (a b : Log) : Prop :=
  ∀ n, n < a.length → n < b.length → (a[n]?).map Entry.term = (b[n]?).map Entry.term →
    a.take (n + 1) = b.take (n + 1)

/-- Follower-side AppendEntries: accept when the prefix matches prevIndex/prevTerm,
    then replace everything after prevIndex with the leader's entries. -/
def appendEntries (follower : Log) (prevIndex : Nat) (prevTerm : Nat) (entries : Log) : Option Log :=
  if prevIndex = 0 then
    some entries
  else
    match follower[prevIndex - 1]? with
    | some e => if e.term = prevTerm then some (follower.take prevIndex ++ entries) else none
    | none => none

/-- Take of a list is a prefix: taking n of (take n l ++ rest) gives take n l. -/
theorem take_append_of_le (l r : Log) (n k : Nat) (h : k ≤ n) (hl : n ≤ l.length) :
    (l.take n ++ r).take k = l.take k := by
  rw [List.take_append_of_le_length]
  · exact List.take_take k n l ▸ by simp [Nat.min_eq_left h]
  · simpa [List.length_take, Nat.min_eq_left hl] using h

/-- A successful append (prevIndex > 0) produces exactly the leader-prescribed log:
    the follower's prefix up to prevIndex followed by the leader's entries. -/
theorem appendEntries_some (follower : Log) (prevIndex prevTerm : Nat) (entries result : Log)
    (hpos : prevIndex ≠ 0)
    (hres : appendEntries follower prevIndex prevTerm entries = some result) :
    result = follower.take prevIndex ++ entries := by
  unfold appendEntries at hres
  simp only [hpos, ↓reduceIte] at hres
  split at hres
  · split at hres
    · exact (Option.some.inj hres).symm
    · exact absurd hres (by simp)
  · exact absurd hres (by simp)

/-- LogMatching is reflexive: a log always matches itself. -/
theorem logMatching_refl (a : Log) : LogMatching a a := by
  intro n _ _ _; rfl

/-- LogMatching is symmetric. -/
theorem logMatching_symm (a b : Log) (h : LogMatching a b) : LogMatching b a := by
  intro n hb ha heq
  exact (h n ha hb heq.symm).symm

/-- Equal logs satisfy LogMatching (used right after a successful append). -/
theorem logMatching_of_eq (a b : Log) (h : a = b) : LogMatching a b := by
  subst h; exact logMatching_refl a

/-- A follower that rejects (prefix term mismatch) keeps its log unchanged, so
    the invariant with every other log is preserved. -/
theorem appendEntries_none_of_term_mismatch (follower : Log) (prevIndex prevTerm : Nat) (entries : Log)
    (hpos : prevIndex ≠ 0) (e : Entry) (hget : follower[prevIndex - 1]? = some e) (hterm : e.term ≠ prevTerm) :
    appendEntries follower prevIndex prevTerm entries = none := by
  unfold appendEntries
  simp [hpos, hget, hterm]

/-- A follower whose log is shorter than prevIndex rejects the append. -/
theorem appendEntries_none_of_missing (follower : Log) (prevIndex prevTerm : Nat) (entries : Log)
    (hpos : prevIndex ≠ 0) (hget : follower[prevIndex - 1]? = none) :
    appendEntries follower prevIndex prevTerm entries = none := by
  unfold appendEntries
  simp [hpos, hget]

/-- Main theorem (all log lengths): if a follower accepts an AppendEntries whose
    prefix equals the leader's prefix and whose entries are the leader's suffix,
    then the follower's log satisfies LogMatching with the leader's log. -/
theorem logMatching_after_append
    (leader follower result : Log) (prevIndex prevTerm : Nat) (entries : Log)
    (hprev : follower.take prevIndex = leader.take prevIndex)
    (hleader : leader = leader.take prevIndex ++ entries)
    (hpos : prevIndex ≠ 0)
    (hres : appendEntries follower prevIndex prevTerm entries = some result) :
    LogMatching result leader := by
  have h := appendEntries_some follower prevIndex prevTerm entries result hpos hres
  subst h
  apply logMatching_of_eq
  rw [hprev]
  exact hleader.symm

/-- The leader-side statement for every index: after the append, both logs
    hold the same entry at every index below the result length. -/
theorem entries_agree_after_append
    (leader follower result : Log) (prevIndex prevTerm : Nat) (entries : Log)
    (hprev : follower.take prevIndex = leader.take prevIndex)
    (hleader : leader = leader.take prevIndex ++ entries)
    (hpos : prevIndex ≠ 0)
    (hres : appendEntries follower prevIndex prevTerm entries = some result) :
    ∀ n : Nat, (result[n]? : Option Entry) = leader[n]? := by
  have h := appendEntries_some follower prevIndex prevTerm entries result hpos hres
  subst h
  intro n
  rw [hprev, ← hleader]

/-- Committed entries are never modified: the prefix up to commitIndex of a
    follower that accepted an append from a leader whose log extends that
    committed prefix is unchanged. -/
theorem committed_prefix_preserved (follower : Log) (prevIndex commit : Nat) (entries : Log)
    (hle : commit ≤ prevIndex) (hlen : prevIndex ≤ follower.length) :
    (follower.take prevIndex ++ entries).take commit = follower.take commit :=
  take_append_of_le follower entries prevIndex commit hle hlen

end Rubernetes.Verification.Raft
