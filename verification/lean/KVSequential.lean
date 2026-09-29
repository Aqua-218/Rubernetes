/-
  Sequential key/value reference model used as the linearizability oracle
  (spec/verification/testing.md 8.3: "逐次モデルは Lean から抽出した参照実装").

  The model is executable: `main` reads a JSON array of operations from
  stdin and writes the expected outputs.  tools/verification/kv_sequential_oracle.rb
  runs it with `lean --run` and compares the outputs against the Ruby model in
  tools/verification/linearizability.rb.  Per D4 the Lean executable is a test
  oracle only; production Ruby is never replaced by extracted code.

  Semantics: a global revision increments on every successful mutation and
  becomes the version of the written key; create fails on an existing key,
  update/delete fail with not_found on a missing key and with conflict when
  the expected version differs from the current one; read returns the value
  and version.
-/
import Lean.Data.Json

open Lean

namespace Rubernetes.Verification.KV

structure Obj where
  value : Json
  version : Nat

structure State where
  revision : Nat
  objects : List (String × Obj)

def State.initial : State := { revision := 0, objects := [] }

def State.get (s : State) (k : String) : Option Obj :=
  (s.objects.find? (fun p => p.1 == k)).map Prod.snd

def State.put (s : State) (k : String) (o : Obj) : State :=
  { s with objects := (k, o) :: s.objects.filter (fun p => p.1 != k) }

def State.remove (s : State) (k : String) : State :=
  { s with objects := s.objects.filter (fun p => p.1 != k) }

structure Op where
  op : String
  key : String
  value : Json
  expectedVersion : Option Nat

def status (s : String) : Json := Json.mkObj [("status", Json.str s)]

/-- Natural number as a JSON number. -/
def jnat (n : Nat) : Json := Json.num (JsonNumber.fromNat n)

def step (s : State) (o : Op) : State × Json :=
  match o.op with
  | "create" =>
    match s.get o.key with
    | some _ => (s, status "already_exists")
    | none =>
      let rev := s.revision + 1
      ({ (s.put o.key { value := o.value, version := rev }) with revision := rev },
       Json.mkObj [("status", Json.str "ok"), ("version", jnat rev)])
  | "update" =>
    match s.get o.key with
    | none => (s, status "not_found")
    | some cur =>
      match o.expectedVersion with
      | some ev =>
        if ev != cur.version then
          (s, Json.mkObj [("status", Json.str "conflict"), ("current_version", jnat cur.version)])
        else
          let rev := s.revision + 1
          ({ (s.put o.key { value := o.value, version := rev }) with revision := rev },
           Json.mkObj [("status", Json.str "ok"), ("version", jnat rev)])
      | none =>
        let rev := s.revision + 1
        ({ (s.put o.key { value := o.value, version := rev }) with revision := rev },
         Json.mkObj [("status", Json.str "ok"), ("version", jnat rev)])
  | "delete" =>
    match s.get o.key with
    | none => (s, status "not_found")
    | some cur =>
      match o.expectedVersion with
      | some ev =>
        if ev != cur.version then
          (s, Json.mkObj [("status", Json.str "conflict"), ("current_version", jnat cur.version)])
        else
          let rev := s.revision + 1
          ({ (s.remove o.key) with revision := rev },
           Json.mkObj [("status", Json.str "ok"), ("version", jnat rev)])
      | none =>
        let rev := s.revision + 1
        ({ (s.remove o.key) with revision := rev },
         Json.mkObj [("status", Json.str "ok"), ("version", jnat rev)])
  | "read" =>
    match s.get o.key with
    | none => (s, status "not_found")
    | some cur => (s, Json.mkObj [("status", Json.str "ok"), ("value", cur.value), ("version", jnat cur.version)])
  | _ => (s, status "unknown_operation")

/-- Run a sequence of operations from the initial state. -/
def run (ops : List Op) : List Json :=
  let rec go (s : State) (rest : List Op) (acc : List Json) : List Json :=
    match rest with
    | [] => acc.reverse
    | o :: tl =>
      let (s', out) := step s o
      go s' tl (out :: acc)
  go State.initial ops []

/-- Determinism: the same operation sequence yields the same outputs (definitional). -/
theorem run_deterministic (ops : List Op) : run ops = run ops := rfl

/-- create on a missing key always succeeds with version revision+1. -/
theorem create_fresh (s : State) (o : Op) (hop : o.op = "create") (hmiss : s.get o.key = none) :
    (step s o).2 = Json.mkObj [("status", Json.str "ok"), ("version", jnat (s.revision + 1))] := by
  simp [step, hop, hmiss]

/-- A mutation with a stale expected version is rejected and leaves the state unchanged. -/
theorem update_conflict_unchanged (s : State) (o : Op) (cur : Obj) (ev : Nat)
    (hop : o.op = "update") (hcur : s.get o.key = some cur) (hev : o.expectedVersion = some ev)
    (hne : ev ≠ cur.version) : (step s o).1 = s := by
  have hne' : (ev != cur.version) = true := by
    simpa [bne_iff_ne] using hne
  simp [step, hop, hcur, hev, hne']

def parseOp (j : Json) : Except String Op := do
  let op ← j.getObjValAs? String "op"
  let key ← j.getObjValAs? String "key"
  let value := (j.getObjVal? "value").toOption.getD Json.null
  let expected := (j.getObjValAs? Nat "expected_version").toOption
  pure { op := op, key := key, value := value, expectedVersion := expected }

end Rubernetes.Verification.KV

open Rubernetes.Verification.KV in
def main : IO Unit := do
  let stdin ← IO.getStdin
  let mut input := ""
  repeat
    let line ← stdin.getLine
    if line.isEmpty then break
    input := input ++ line
  match Json.parse input with
  | .error e => IO.eprintln s!"invalid JSON: {e}"; IO.Process.exit 2
  | .ok json =>
    match json.getArr? with
    | .error e => IO.eprintln s!"expected an array: {e}"; IO.Process.exit 2
    | .ok arr =>
      let parsed := arr.toList.mapM parseOp
      match parsed with
      | .error e => IO.eprintln s!"invalid operation: {e}"; IO.Process.exit 2
      | .ok ops =>
        let outputs := run ops
        IO.println (Json.arr outputs.toArray).compress
