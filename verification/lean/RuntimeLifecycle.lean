import Std

namespace Rubernetes.Verification

/-
  Executable reference model for the M2 runtime lifecycle.

  The model is intentionally small: one sandbox, a finite resource enum, and
  Boolean resource maps.  Resource maps avoid depending on Mathlib while still
  making the ownership and release implications fully quantified over every
  resource.  This file is compiled directly by `lean`; it has no external
  proof profile and contains only closed theorem declarations.
-/

inductive Phase where
  | new
  | validated
  | imagePinned
  | workspaceAllocated
  | isolationCreated
  | resourcesAttached
  | workloadStopped
  | running
  | stopping
  | stopped
  | removed
  | rollingBack
  | cleanupPending
  | stateUnknown
deriving DecidableEq, Repr

inductive Resource where
  | workspace
  | isolation
  | attachment
  | process
deriving DecidableEq, Repr

inductive NextAction where
  | noAction
  | cleanupOrObserve
deriving DecidableEq, Repr

inductive Action where
  | validate
  | pinImage
  | rejectDigest
  | allocateWorkspace
  | createIsolation
  | attachResources
  | closeWorkloadGate
  | releaseGate
  | beginStopping
  | confirmStopped
  | cleanupOne (resource : Resource)
  | finishRollback
  | remove
  | failure
  | ambiguous
  | observeProcess
  | reconcileUnknown
  | retryCleanup
  | markCleanupPending
deriving DecidableEq, Repr

abbrev ResourceMap := Resource → Bool

def emptyMap : ResourceMap := fun _ => false

def insertResource (resources : ResourceMap) (resource : Resource) : ResourceMap :=
  fun candidate => if candidate = resource then true else resources candidate

def removeResource (resources : ResourceMap) (resource : Resource) : ResourceMap :=
  fun candidate => if candidate = resource then false else resources candidate

structure Snapshot where
  phase : Phase
  liveOwner : ResourceMap
  released : ResourceMap
  ownedResources : ResourceMap
  sandboxReady : Bool
  digestMismatch : Bool
  noWorkloadEffect : Bool
  nextAction : NextAction
  liveProcess : Bool

def initial : Snapshot :=
  { phase := .new
    liveOwner := emptyMap
    released := emptyMap
    ownedResources := emptyMap
    sandboxReady := false
    digestMismatch := false
    noWorkloadEffect := true
    nextAction := .noAction
    liveProcess := false }

def LiveOwner (snapshot : Snapshot) : Prop :=
  ∀ resource, snapshot.liveOwner resource = true → snapshot.released resource = false

def RunningSandboxReady (snapshot : Snapshot) : Prop :=
  snapshot.phase = .running → snapshot.sandboxReady = true

def DigestMismatchNoWorkloadEffect (snapshot : Snapshot) : Prop :=
  snapshot.digestMismatch = true → snapshot.noWorkloadEffect = true

def UnknownOnlyCleanupOrObserve (snapshot : Snapshot) : Prop :=
  snapshot.phase = .stateUnknown → snapshot.nextAction = .cleanupOrObserve

def StoppedHasNoLiveProcess (snapshot : Snapshot) : Prop :=
  snapshot.phase = .stopped → snapshot.liveProcess = false

def RemovedHasNoResources (snapshot : Snapshot) : Prop :=
  snapshot.phase = .removed → ∀ resource, snapshot.ownedResources resource = false

def Safe (snapshot : Snapshot) : Prop :=
  LiveOwner snapshot ∧
  RunningSandboxReady snapshot ∧
  DigestMismatchNoWorkloadEffect snapshot ∧
  UnknownOnlyCleanupOrObserve snapshot ∧
  StoppedHasNoLiveProcess snapshot ∧
  RemovedHasNoResources snapshot

theorem insert_at_resource (resources : ResourceMap) (resource : Resource) :
    insertResource resources resource resource = true := by
  simp [insertResource]

theorem insert_at_other_resource (resources : ResourceMap) (resource candidate : Resource)
    (different : candidate ≠ resource) :
    insertResource resources resource candidate = resources candidate := by
  simp [insertResource, different]

theorem remove_at_resource (resources : ResourceMap) (resource : Resource) :
    removeResource resources resource resource = false := by
  simp [removeResource]

theorem remove_at_other_resource (resources : ResourceMap) (resource candidate : Resource)
    (different : candidate ≠ resource) :
    removeResource resources resource candidate = resources candidate := by
  simp [removeResource, different]

def claim (snapshot : Snapshot) (resource : Resource) : Snapshot :=
  { snapshot with
    liveOwner := insertResource snapshot.liveOwner resource
    ownedResources := insertResource snapshot.ownedResources resource }

def release (snapshot : Snapshot) (resource : Resource) : Snapshot :=
  { snapshot with
    liveOwner := removeResource snapshot.liveOwner resource
    ownedResources := removeResource snapshot.ownedResources resource
    released := insertResource snapshot.released resource }

theorem live_owner_after_claim (snapshot : Snapshot) (resource : Resource)
    (safe : LiveOwner snapshot)
    (not_released : snapshot.released resource = false) :
    LiveOwner (claim snapshot resource) := by
  intro candidate owner
  by_cases equal : candidate = resource
  · subst candidate
    simpa [claim, insertResource] using not_released
  · have previous_owner : snapshot.liveOwner candidate = true := by
      simpa [claim, insertResource, equal] using owner
    have previous_release := safe candidate previous_owner
    simpa [claim, insertResource, equal] using previous_release

theorem live_owner_after_release (snapshot : Snapshot) (resource : Resource)
    (safe : LiveOwner snapshot) :
    LiveOwner (release snapshot resource) := by
  intro candidate owner
  by_cases equal : candidate = resource
  · subst candidate
    simp [release, removeResource] at owner
  · have previous_owner : snapshot.liveOwner candidate = true := by
      simpa [release, removeResource, equal] using owner
    have previous_release := safe candidate previous_owner
    simpa [release, insertResource, equal] using previous_release

theorem safe_after_claim (snapshot : Snapshot) (resource : Resource)
    (safe : Safe snapshot)
    (not_released : snapshot.released resource = false)
    (not_removed : snapshot.phase ≠ .removed) :
    Safe (claim snapshot resource) := by
  rcases safe with ⟨owner_safe, running_safe, digest_safe, unknown_safe, stopped_safe,
    removed_safe⟩
  refine ⟨live_owner_after_claim snapshot resource owner_safe not_released, ?_, ?_, ?_, ?_, ?_⟩
  · exact running_safe
  · exact digest_safe
  · exact unknown_safe
  · exact stopped_safe
  · intro phase_removed
    exact (not_removed phase_removed).elim

theorem safe_after_release (snapshot : Snapshot) (resource : Resource)
    (safe : Safe snapshot) :
    Safe (release snapshot resource) := by
  rcases safe with ⟨owner_safe, running_safe, digest_safe, unknown_safe, stopped_safe,
    removed_safe⟩
  refine ⟨live_owner_after_release snapshot resource owner_safe, ?_, ?_, ?_, ?_, ?_⟩
  · exact running_safe
  · exact digest_safe
  · exact unknown_safe
  · exact stopped_safe
  · intro phase_removed candidate
    have previous_empty := removed_safe phase_removed candidate
    by_cases equal : candidate = resource
    · subst candidate
      simp [release, removeResource]
    · simpa [release, removeResource, equal] using previous_empty

def runningFromWorkloadStopped (snapshot : Snapshot) : Snapshot :=
  { claim snapshot .process with
    phase := .running
    sandboxReady := true
    noWorkloadEffect := false
    liveProcess := true }

def stoppedFromStopping (snapshot : Snapshot) : Snapshot :=
  { snapshot with phase := .stopped, liveProcess := false }

def rollbackFromFailure (snapshot : Snapshot) : Snapshot :=
  { snapshot with
    phase := .rollingBack
    nextAction := .cleanupOrObserve
    noWorkloadEffect := true
    liveProcess := false }

def unknownFromAmbiguous (snapshot : Snapshot) : Snapshot :=
  { snapshot with
    phase := .stateUnknown
    nextAction := .cleanupOrObserve }

inductive Step : Snapshot → Action → Snapshot → Prop where
  | validate {snapshot} (phase : snapshot.phase = .new) :
      Step snapshot .validate { snapshot with phase := .validated }
  | pinImage {snapshot} (phase : snapshot.phase = .validated)
      (digest : snapshot.digestMismatch = false) :
      Step snapshot .pinImage { snapshot with phase := .imagePinned }
  | rejectDigest {snapshot} (phase : snapshot.phase = .new ∨ snapshot.phase = .validated)
      (digest : snapshot.digestMismatch = false) :
      Step snapshot .rejectDigest
        { snapshot with
          phase := .stateUnknown
          digestMismatch := true
          noWorkloadEffect := true
          nextAction := .cleanupOrObserve
          liveProcess := false }
  | allocateWorkspace {snapshot}
      (phase : snapshot.phase = .imagePinned)
      (released : snapshot.released .workspace = false)
      (owner : snapshot.liveOwner .workspace = false)
      (owned : snapshot.ownedResources .workspace = false) :
      Step snapshot .allocateWorkspace (claim { snapshot with phase := .workspaceAllocated } .workspace)
  | createIsolation {snapshot}
      (phase : snapshot.phase = .workspaceAllocated)
      (released : snapshot.released .isolation = false)
      (owner : snapshot.liveOwner .isolation = false)
      (owned : snapshot.ownedResources .isolation = false) :
      Step snapshot .createIsolation (claim { snapshot with phase := .isolationCreated } .isolation)
  | attachResources {snapshot}
      (phase : snapshot.phase = .isolationCreated)
      (released : snapshot.released .attachment = false)
      (owner : snapshot.liveOwner .attachment = false)
      (owned : snapshot.ownedResources .attachment = false) :
      Step snapshot .attachResources (claim { snapshot with phase := .resourcesAttached } .attachment)
  | closeWorkloadGate {snapshot} (phase : snapshot.phase = .resourcesAttached) :
      Step snapshot .closeWorkloadGate
        { snapshot with
          phase := .workloadStopped
          sandboxReady := true
          noWorkloadEffect := true
          liveProcess := false }
  | releaseGate {snapshot}
      (phase : snapshot.phase = .workloadStopped)
      (digest : snapshot.digestMismatch = false)
      (ready : snapshot.sandboxReady = true)
      (released : snapshot.released .process = false)
      (owner : snapshot.liveOwner .process = false)
      (owned : snapshot.ownedResources .process = false) :
      Step snapshot .releaseGate (runningFromWorkloadStopped snapshot)
  | beginStopping {snapshot} (phase : snapshot.phase = .running) :
      Step snapshot .beginStopping { snapshot with phase := .stopping, liveProcess := false }
  | confirmStopped {snapshot} (phase : snapshot.phase = .stopping)
      (no_process : snapshot.liveProcess = false) :
      Step snapshot .confirmStopped (stoppedFromStopping snapshot)
  | cleanupOne {snapshot} (resource : Resource)
      (phase : snapshot.phase = .stopped ∨ snapshot.phase = .rollingBack)
      (no_process : snapshot.liveProcess = false)
      (owned : snapshot.liveOwner resource = true) :
      Step snapshot (.cleanupOne resource) (release snapshot resource)
  | finishRollback {snapshot}
      (phase : snapshot.phase = .rollingBack)
      (no_process : snapshot.liveProcess = false)
      (empty : ∀ resource, snapshot.ownedResources resource = false) :
      Step snapshot .finishRollback { snapshot with phase := .stopped }
  | remove {snapshot}
      (phase : snapshot.phase = .stopped)
      (no_process : snapshot.liveProcess = false)
      (empty : ∀ resource, snapshot.ownedResources resource = false) :
      Step snapshot .remove { snapshot with phase := .removed }
  | failure {snapshot}
      (phase : snapshot.phase = .workspaceAllocated ∨
        snapshot.phase = .isolationCreated ∨
        snapshot.phase = .resourcesAttached ∨
        snapshot.phase = .workloadStopped) :
      Step snapshot .failure (rollbackFromFailure snapshot)
  | ambiguous {snapshot}
      (phase : snapshot.phase = .workspaceAllocated ∨
        snapshot.phase = .isolationCreated ∨
        snapshot.phase = .resourcesAttached ∨
        snapshot.phase = .workloadStopped ∨
        snapshot.phase = .running ∨
        snapshot.phase = .stopping) :
      Step snapshot .ambiguous (unknownFromAmbiguous snapshot)
  | observeProcess {snapshot} (phase : snapshot.phase = .stateUnknown)
      (action : snapshot.nextAction = .cleanupOrObserve) :
      Step snapshot .observeProcess { snapshot with liveProcess := false }
  | reconcileUnknown {snapshot} (phase : snapshot.phase = .stateUnknown)
      (action : snapshot.nextAction = .cleanupOrObserve)
      (no_process : snapshot.liveProcess = false) :
      Step snapshot .reconcileUnknown { snapshot with phase := .stopping }
  | retryCleanup {snapshot} (phase : snapshot.phase = .cleanupPending)
      (action : snapshot.nextAction = .cleanupOrObserve) :
      Step snapshot .retryCleanup { snapshot with phase := .rollingBack }
  | markCleanupPending {snapshot}
      (phase : snapshot.phase = .rollingBack ∨ snapshot.phase = .stopped) :
      Step snapshot .markCleanupPending
        { snapshot with phase := .cleanupPending, nextAction := .cleanupOrObserve }

theorem step_preserves_safety {snapshot : Snapshot} {action : Action} {next : Snapshot}
    (safe : Safe snapshot) (step : Step snapshot action next) : Safe next := by
  rcases safe with ⟨owner_safe, running_safe, digest_safe, unknown_safe, stopped_safe,
    removed_safe⟩
  have safe_snapshot : Safe snapshot :=
    ⟨owner_safe, running_safe, digest_safe, unknown_safe, stopped_safe, removed_safe⟩
  cases step with
  | validate phase =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using ⟨owner_safe, digest_safe⟩
  | pinImage phase digest =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, digest] using owner_safe
  | rejectDigest phase digest =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, digest] using owner_safe
  | allocateWorkspace phase released owner owned =>
      have claimed := safe_after_claim snapshot .workspace ⟨owner_safe, running_safe,
        digest_safe, unknown_safe, stopped_safe, removed_safe⟩ released
        (by intro removed; rw [phase] at removed; cases removed)
      simpa [claim, Safe, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using claimed
  | createIsolation phase released owner owned =>
      have claimed := safe_after_claim snapshot .isolation ⟨owner_safe, running_safe,
        digest_safe, unknown_safe, stopped_safe, removed_safe⟩ released
        (by intro removed; rw [phase] at removed; cases removed)
      simpa [claim, Safe, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using claimed
  | attachResources phase released owner owned =>
      have claimed := safe_after_claim snapshot .attachment ⟨owner_safe, running_safe,
        digest_safe, unknown_safe, stopped_safe, removed_safe⟩ released
        (by intro removed; rw [phase] at removed; cases removed)
      simpa [claim, Safe, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using claimed
  | closeWorkloadGate phase =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using owner_safe
  | releaseGate phase digest ready released owner owned =>
      have claimed := safe_after_claim snapshot .process ⟨owner_safe, running_safe,
        digest_safe, unknown_safe, stopped_safe, removed_safe⟩ released
        (by intro removed_state; rw [phase] at removed_state; cases removed_state)
      simpa [runningFromWorkloadStopped, claim, Safe, LiveOwner,
        RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, digest, ready] using claimed
  | beginStopping phase =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using ⟨owner_safe, digest_safe⟩
  | confirmStopped phase no_process =>
      refine ⟨owner_safe, ?_, digest_safe, ?_, ?_, ?_⟩
      · simp [RunningSandboxReady, stoppedFromStopping]
      · simp [UnknownOnlyCleanupOrObserve, stoppedFromStopping]
      · simp [stoppedFromStopping, StoppedHasNoLiveProcess, no_process]
      · simp [RemovedHasNoResources, stoppedFromStopping]
  | cleanupOne resource phase no_process owned =>
      have released_state := safe_after_release snapshot resource
        ⟨owner_safe, running_safe, digest_safe, unknown_safe, stopped_safe, removed_safe⟩
      simpa [Safe, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, no_process] using released_state
  | finishRollback phase no_process empty =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, no_process, empty] using ⟨owner_safe, digest_safe⟩
  | remove phase no_process empty =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, no_process, empty] using ⟨owner_safe, digest_safe⟩
  | failure phase =>
      simpa [rollbackFromFailure, Safe, LiveOwner, RunningSandboxReady,
        DigestMismatchNoWorkloadEffect, UnknownOnlyCleanupOrObserve,
        StoppedHasNoLiveProcess, RemovedHasNoResources, phase] using owner_safe
  | ambiguous phase =>
      simpa [unknownFromAmbiguous, Safe, LiveOwner, RunningSandboxReady,
        DigestMismatchNoWorkloadEffect, UnknownOnlyCleanupOrObserve,
        StoppedHasNoLiveProcess, RemovedHasNoResources, phase] using ⟨owner_safe, digest_safe⟩
  | observeProcess phase action =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, action] using ⟨owner_safe, digest_safe⟩
  | reconcileUnknown phase action no_process =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, action, no_process] using ⟨owner_safe, digest_safe⟩
  | retryCleanup phase action =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase, action] using ⟨owner_safe, digest_safe⟩
  | markCleanupPending phase =>
      simpa [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
        UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
        phase] using ⟨owner_safe, digest_safe⟩

theorem initial_is_safe : Safe initial := by
  simp [Safe, LiveOwner, RunningSandboxReady, DigestMismatchNoWorkloadEffect,
    UnknownOnlyCleanupOrObserve, StoppedHasNoLiveProcess, RemovedHasNoResources,
    initial, emptyMap]

inductive Reachable : Snapshot → Prop where
  | initial : Reachable initial
  | step {snapshot next : Snapshot} {action : Action} :
      Reachable snapshot → Step snapshot action next → Reachable next

theorem reachable_is_safe {snapshot : Snapshot} (reachable : Reachable snapshot) :
    Safe snapshot := by
  induction reachable with
  | initial => exact initial_is_safe
  | @step snapshot next action reached transition induction_hypothesis =>
      exact step_preserves_safety induction_hypothesis transition

end Rubernetes.Verification
