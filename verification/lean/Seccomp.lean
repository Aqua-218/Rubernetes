import Lean

/-!
Seccomp compiler (spec/verification/formal-methods.md §7.3).
An incorrect lowering could permit a forbidden syscall or deny a required one.
The proof works at the word-comparison and forward-branch level. Opcode layout,
jump offsets, the manifest and action encoding are exercised by the Ruby
differential oracle against the production compiler and BPF interpreter.
-/

namespace Rubernetes.Verification.Seccomp

inductive Operator where
  | eq | ne | lt | le | gt | ge | maskedEq

def argumentMatches (operator : Operator) (actual value expected : Nat) : Bool :=
  match operator with
  | .eq => actual == value
  | .ne => actual != value
  | .lt => decide (actual < value)
  | .le => decide (actual ≤ value)
  | .gt => decide (value < actual)
  | .ge => decide (value ≤ actual)
  | .maskedEq => (actual &&& value) == expected

private def highWord (value : Nat) : Nat := value / 2 ^ 32
private def lowWord (value : Nat) : Nat := value % 2 ^ 32

private theorem highWord_and (a b : Nat) :
    highWord (a &&& b) = highWord a &&& highWord b :=
  Nat.and_div_two_pow

private theorem lowWord_and (a b : Nat) :
    lowWord (a &&& b) = lowWord a &&& lowWord b := by
  unfold lowWord
  simp only [← Nat.and_pow_two_sub_one_eq_mod]
  calc
    a &&& b &&& (2 ^ 32 - 1) = a &&& b &&& ((2 ^ 32 - 1) &&& (2 ^ 32 - 1)) := by simp
    _ = (a &&& (2 ^ 32 - 1)) &&& (b &&& (2 ^ 32 - 1)) := by ac_rfl

/-- The two 32-bit loads and conditional branches emitted by emit_condition. -/
def wordChecks (operator : Operator) (actual value expected : Nat) : Bool :=
  let high := highWord actual
  let low := lowWord actual
  let valueHigh := highWord value
  let valueLow := lowWord value
  match operator with
  | .eq => if high = valueHigh then low == valueLow else false
  | .ne => if high = valueHigh then low != valueLow else true
  | .lt => if valueHigh < high then false else if high = valueHigh then decide (low < valueLow) else true
  | .le => if valueHigh < high then false else if high = valueHigh then decide (low ≤ valueLow) else true
  | .gt => if valueHigh < high then true else if high = valueHigh then decide (valueLow < low) else false
  | .ge => if valueHigh < high then true else if high = valueHigh then decide (valueLow ≤ low) else false
  | .maskedEq =>
    if (high &&& valueHigh) = highWord expected
    then (low &&& valueLow) == lowWord expected
    else false

theorem word_checks_preserve_argument_matching (operator : Operator) (actual value expected : Nat) :
    wordChecks operator actual value expected = argumentMatches operator actual value expected := by
  cases operator <;> simp only [wordChecks, argumentMatches, ← highWord_and, ← lowWord_and] <;>
    split <;> (try split) <;> apply Bool.eq_iff_iff.mpr <;>
    simp [highWord, lowWord] at * <;> omega

structure Condition where
  index : Nat
  operator : Operator
  value : Nat
  expected : Nat

structure Rule where
  numbers : List Nat
  conditions : List Condition
  result : Nat

abbrev Arguments := List (Nat)

def Condition.matches (condition : Condition) (arguments : Arguments) : Bool :=
  argumentMatches condition.operator (arguments[condition.index]?.getD 0) condition.value condition.expected

def Condition.check (condition : Condition) (arguments : Arguments) : Bool :=
  wordChecks condition.operator (arguments[condition.index]?.getD 0) condition.value condition.expected

def evaluate (fallback nr : Nat) (arguments : Arguments) : List Rule → Nat
  | [] => fallback
  | rule :: rest =>
    if rule.numbers.contains nr && rule.conditions.all (·.matches arguments)
    then rule.result
    else evaluate fallback nr arguments rest

/-- Forward-only branches corresponding to the next-rule and success labels.
Each rule starts with the syscall number reloaded independently of the argument
comparison accumulator. -/
inductive Program where
  | ret (result : Nat)
  | checkNumber (numbers : List Nat) (matched skipped : Program)
  | checkArgument (condition : Condition) (matched skipped : Program)

def compileConditions (conditions : List Condition) (matched skipped : Program) : Program :=
  conditions.foldr (fun condition next => .checkArgument condition next skipped) matched

def compile (rules : List Rule) (fallback : Nat) : Program :=
  rules.foldr (fun rule next =>
    .checkNumber rule.numbers (compileConditions rule.conditions (.ret rule.result) next) next) (.ret fallback)

def run (nr : Nat) (arguments : Arguments) : Program → Nat
  | .ret result => result
  | .checkNumber numbers matched skipped =>
    if numbers.contains nr then run nr arguments matched else run nr arguments skipped
  | .checkArgument condition matched skipped =>
    if condition.check arguments then run nr arguments matched else run nr arguments skipped

theorem run_conditions (conditions : List Condition) (matched skipped : Program) (nr : Nat) (arguments : Arguments) :
    run nr arguments (compileConditions conditions matched skipped) =
      if conditions.all (·.matches arguments) then run nr arguments matched else run nr arguments skipped := by
  induction conditions with
  | nil => simp [compileConditions]
  | cons condition remaining ih =>
    change run nr arguments (.checkArgument condition (compileConditions remaining matched skipped) skipped) = _
    have check : condition.check arguments = condition.matches arguments :=
      word_checks_preserve_argument_matching _ _ _ _
    simp only [run, check, ih, List.all_cons]
    split <;> simp_all

theorem compilation_preserves_ordered_rule_semantics
    (rules : List Rule) (fallback nr : Nat) (arguments : Arguments) :
    run nr arguments (compile rules fallback) = evaluate fallback nr arguments rules := by
  induction rules with
  | nil => simp [compile, evaluate, run]
  | cons rule remaining ih =>
    change run nr arguments (.checkNumber rule.numbers
      (compileConditions rule.conditions (.ret rule.result) (compile remaining fallback))
      (compile remaining fallback)) = _
    simp only [run, run_conditions, evaluate]
    cases nums : rule.numbers.contains nr <;> cases args : rule.conditions.all (·.matches arguments) <;>
      simp [nums, args, ih]

end Rubernetes.Verification.Seccomp

open Lean Rubernetes.Verification.Seccomp

private def parseCondition (input : Json) : Except String Condition := do
  let operator ← match ← input.getObjValAs? String "op" with
    | "SCMP_CMP_EQ" => pure Operator.eq
    | "SCMP_CMP_NE" => pure Operator.ne
    | "SCMP_CMP_LT" => pure Operator.lt
    | "SCMP_CMP_LE" => pure Operator.le
    | "SCMP_CMP_GT" => pure Operator.gt
    | "SCMP_CMP_GE" => pure Operator.ge
    | "SCMP_CMP_MASKED_EQ" => pure Operator.maskedEq
    | name => throw s!"unknown operator: {name}"
  return {
    index := ← input.getObjValAs? Nat "index"
    operator
    value := ← input.getObjValAs? Nat "value"
    expected := ← input.getObjValAs? Nat "valueTwo"
  }

private def parseRule (input : Json) : Except String Rule := do
  return {
    numbers := ← input.getObjValAs? (List Nat) "numbers"
    conditions := ← (← input.getObjValAs? (List Json) "conditions").mapM parseCondition
    result := ← input.getObjValAs? Nat "result"
  }

private def runCase (input : Json) : Except String Nat := do
  let rules ← (← input.getObjValAs? (List Json) "rules").mapM parseRule
  let fallback ← input.getObjValAs? Nat "fallback"
  let nr ← input.getObjValAs? Nat "nr"
  let arguments ← input.getObjValAs? (List Nat) "arguments"
  return run nr arguments (compile rules fallback)

def main : IO Unit := do
  let stdin ← IO.getStdin
  let input ← stdin.getLine
  let result := do
    let cases ← (← Json.parse input).getArr?
    cases.mapM runCase
  match result with
  | .ok results => IO.println (toJson results).compress
  | .error message => throw (IO.userError message)
