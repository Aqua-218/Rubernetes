import Lean

/-!
Schema field-set parity (spec/verification/formal-methods.md §7.3).
A missing field on one surface can cause an accepted API field to be dropped
by a codec or omitted from patch handling. This proves the semantic field-set
checker. The Ruby renderer and artifact parsers remain outside Lean. RBS
accessor method names are a projection of the semantic fields.
-/

namespace Rubernetes.Verification.Schema

structure Surfaces where
  ruby : List String
  rbs : List String
  codec : List String
  openapi : List String
  patch : List String
deriving Lean.FromJson

def Surfaces.fieldLists (s : Surfaces) : List (List String) :=
  [s.ruby, s.rbs, s.codec, s.openapi, s.patch]

def contained (left right : List String) : Bool :=
  left.all right.contains

def equalFields (left right : List String) : Bool :=
  contained left right && contained right left

theorem equal_fields_iff_membership (left right : List String) :
    equalFields left right = true ↔ ∀ field, field ∈ left ↔ field ∈ right := by
  simp [equalFields, contained, List.all_eq_true]
  exact ⟨fun h field => ⟨h.1 field, h.2 field⟩, fun h => ⟨fun f => (h f).mp, fun f => (h f).mpr⟩⟩

def verify (fields : List String) (surfaces : Surfaces) : Bool :=
  surfaces.fieldLists.all (equalFields fields)

theorem check_agrees_with_all_projections (fields : List String) (surfaces : Surfaces) :
    verify fields surfaces = true ↔
      ∀ emitted ∈ surfaces.fieldLists, ∀ field, field ∈ fields ↔ field ∈ emitted := by
  simp only [verify, List.all_eq_true, equal_fields_iff_membership]

end Rubernetes.Verification.Schema

open Lean Rubernetes.Verification.Schema

private def runCase (input : Json) : Except String Bool := do
  let fields ← input.getObjValAs? (List String) "fields"
  let emitted ← input.getObjValAs? Surfaces "surfaces"
  return verify fields emitted

def main : IO Unit := do
  let stdin ← IO.getStdin
  let input ← stdin.getLine
  let result := do
    let cases ← (← Json.parse input).getArr?
    cases.mapM runCase
  match result with
  | .ok cases => IO.println (toJson cases).compress
  | .error message => throw (IO.userError message)
