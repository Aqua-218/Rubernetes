----------------------------- MODULE RuntimeLifecycle -----------------------------

(*
 * M2 Native runtime lifecycle model.
 *
 * This model follows spec/node/runtime.md sections 5.8.3, 5.8.4, and
 * 5.8.14.  The resource universe is deliberately the complete six-kind M2
 * set: mount, namespace, cgroup, process, pidfd, and temporary workspace.
 * Resources are acquired in dependency order and cleanup can only remove the
 * current stack top.  A released identity is retained in a tombstone set and
 * can never be claimed again during the modeled operation.
 *
 * Apalache understands the @type annotations below.  TLC treats them as
 * comments and checks the same domains through TypeOK.
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANT
  (* @type: Set(Str); *)
  ResourceIds

New == "New"
Validated == "Validated"
ImagePinned == "ImagePinned"
WorkspaceAllocated == "WorkspaceAllocated"
IsolationCreated == "IsolationCreated"
ResourcesAttached == "ResourcesAttached"
WorkloadStopped == "WorkloadStopped"
Running == "Running"
Stopping == "Stopping"
Stopped == "Stopped"
Removed == "Removed"
RollingBack == "RollingBack"
CleanupPending == "CleanupPending"
StateUnknown == "StateUnknown"
Unknown == StateUnknown

States == {
  New, Validated, ImagePinned, WorkspaceAllocated, IsolationCreated,
  ResourcesAttached, WorkloadStopped, Running, Stopping, Stopped, Removed,
  RollingBack, CleanupPending, StateUnknown
}

CleanupOrObserve == "CleanupOrObserve"
NoAction == "NoAction"

Mount == "mount"
Namespace == "ns"
Cgroup == "cgroup"
Process == "process"
Pidfd == "pidfd"
Temporary == "temp"

RequiredResourceKinds == {Mount, Namespace, Cgroup, Process, Pidfd, Temporary}

(* @type: Seq(Str) => Set(Str); *)
SequenceResources(sequence) ==
  {sequence[index] : index \in DOMAIN sequence}

(* Apalache cannot encode the unbounded set Seq(ResourceIds).  The M2 model
   has exactly six identities, so a bounded sequence predicate is sufficient
   for TypeOK while the operator type annotations constrain the element type. *)
(* @type: Seq(Str) => Bool; *)
IsResourceSequence(sequence) ==
  /\ Len(sequence) <= Cardinality(ResourceIds)
  /\ SequenceResources(sequence) \subseteq ResourceIds

(* @type: (Seq(Str), Int) => Seq(Str); *)
Prefix(sequence, count) ==
  IF count = 0 THEN <<>> ELSE SubSeq(sequence, 1, count)

(* @type: (Seq(Str), Seq(Str)) => Bool; *)
DistinctSequence(left, right) ==
  Cardinality(SequenceResources(left \o right)) = Len(left) + Len(right)

VARIABLES
  (* @type: Str; *) state,
  (* @type: Set(Str); *) liveOwner,
  (* @type: Set(Str); *) released,
  (* @type: Set(Str); *) ownedResources,
  (* @type: Seq(Str); *) claimOrder,
  (* @type: Seq(Str); *) acquisitionOrder,
  (* @type: Seq(Str); *) cleanupOrder,
  (* @type: Set(Str); *) claimedResources,
  (* @type: Bool; *) sandboxReady,
  (* @type: Bool; *) digestMismatch,
  (* @type: Bool; *) noWorkloadEffect,
  (* @type: Str; *) nextAction,
  (* @type: Bool; *) liveProcess

vars == <<state, liveOwner, released, ownedResources, claimOrder,
          acquisitionOrder, cleanupOrder, claimedResources, sandboxReady,
          digestMismatch, noWorkloadEffect, nextAction, liveProcess>>

Init ==
  /\ state = New
  /\ liveOwner = {}
  /\ released = {}
  /\ ownedResources = {}
  /\ claimOrder = << >>
  /\ acquisitionOrder = << >>
  /\ cleanupOrder = << >>
  /\ claimedResources = {}
  /\ sandboxReady = FALSE
  /\ digestMismatch = FALSE
  /\ noWorkloadEffect = TRUE
  /\ nextAction = NoAction
  /\ liveProcess = FALSE

TypeOK ==
  /\ ResourceIds = RequiredResourceKinds
  /\ state \in States
  /\ liveOwner \subseteq ResourceIds
  /\ released \subseteq ResourceIds
  /\ ownedResources \subseteq ResourceIds
  /\ IsResourceSequence(claimOrder)
  /\ IsResourceSequence(acquisitionOrder)
  /\ IsResourceSequence(cleanupOrder)
  /\ claimedResources \subseteq ResourceIds
  /\ sandboxReady \in BOOLEAN
  /\ digestMismatch \in BOOLEAN
  /\ noWorkloadEffect \in BOOLEAN
  /\ nextAction \in {CleanupOrObserve, NoAction}
  /\ liveProcess \in BOOLEAN

(* The active ownership sets are exactly the current acquisition stack. *)
ActiveResourceInvariant ==
  /\ liveOwner = SequenceResources(claimOrder)
  /\ ownedResources = SequenceResources(claimOrder)

LiveOwnerInvariant == liveOwner \cap released = {}

(* Every identity is claimed once, and released identities remain tombstones. *)
IdentityNonReuseInvariant ==
  /\ claimedResources = SequenceResources(acquisitionOrder)
  /\ claimedResources = liveOwner \cup released
  /\ LiveOwnerInvariant
  /\ Len(acquisitionOrder) = Cardinality(claimedResources)
  /\ Len(cleanupOrder) = Cardinality(released)

(* Cleanup is the reverse of acquisition, including when cleanup is retried. *)
CleanupOrderInvariant ==
  /\ Len(cleanupOrder) <= Len(acquisitionOrder)
  /\ IF Len(cleanupOrder) = 0 THEN TRUE ELSE
       cleanupOrder[Len(cleanupOrder)] =
         acquisitionOrder[Len(acquisitionOrder) - Len(cleanupOrder) + 1]
  /\ claimOrder = Prefix(acquisitionOrder, Len(acquisitionOrder) - Len(cleanupOrder))

RunningInvariant ==
  /\ state = Running => sandboxReady
  /\ state = Running => ~digestMismatch
  /\ state = Running => ~noWorkloadEffect
  /\ state = Running => liveProcess

DigestMismatchInvariant ==
  /\ digestMismatch => noWorkloadEffect
  /\ digestMismatch => state # Running

WorkloadStoppedInvariant ==
  state = WorkloadStopped =>
    /\ sandboxReady
    /\ noWorkloadEffect
    /\ ~liveProcess

UnknownInvariant ==
  state = StateUnknown => nextAction = CleanupOrObserve

StoppedInvariant ==
  state = Stopped => ~liveProcess

RemovedInvariant ==
  state = Removed =>
    /\ ownedResources = {}
    /\ liveOwner = {}
    /\ ~liveProcess

AllInvariants ==
  /\ TypeOK
  /\ ActiveResourceInvariant
  /\ IdentityNonReuseInvariant
  /\ CleanupOrderInvariant
  /\ RunningInvariant
  /\ DigestMismatchInvariant
  /\ WorkloadStoppedInvariant
  /\ UnknownInvariant
  /\ StoppedInvariant
  /\ RemovedInvariant

NoWorkloadInstruction ==
  /\ noWorkloadEffect' = TRUE
  /\ liveProcess' = FALSE

KeepSafety ==
  /\ sandboxReady' = sandboxReady
  /\ digestMismatch' = digestMismatch
  /\ noWorkloadEffect' = noWorkloadEffect
  /\ nextAction' = nextAction
  /\ liveProcess' = liveProcess

Validate ==
  /\ state = New
  /\ state' = Validated
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources>>
  /\ KeepSafety

PinImage ==
  /\ state = Validated
  /\ ~digestMismatch
  /\ state' = ImagePinned
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources>>
  /\ KeepSafety

(* A mismatch is terminal for workload effects.  It moves to observation and
   cleanup without allocating any resource or guessing successful execution. *)
RejectDigest ==
  /\ state \in {New, Validated}
  /\ ~digestMismatch
  /\ state' = StateUnknown
  /\ digestMismatch' = TRUE
  /\ nextAction' = CleanupOrObserve
  /\ NoWorkloadInstruction
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources, sandboxReady>>

(* ClaimResources appends a unique batch atomically.  Batching allows one
   lifecycle transition to represent the independent mount/namespace and
   cgroup/pidfd effects while retaining their precise acquisition order. *)
ClaimResources(resources) ==
  /\ IsResourceSequence(resources)
  /\ Len(resources) > 0
  /\ Cardinality(SequenceResources(resources)) = Len(resources)
  /\ DistinctSequence(claimOrder, resources)
  /\ SequenceResources(resources) \cap claimedResources = {}
  /\ liveOwner' = liveOwner \cup SequenceResources(resources)
  /\ ownedResources' = ownedResources \cup SequenceResources(resources)
  /\ claimOrder' = claimOrder \o resources
  /\ acquisitionOrder' = acquisitionOrder \o resources
  /\ claimedResources' = claimedResources \cup SequenceResources(resources)

AllocateWorkspace ==
  /\ state = ImagePinned
  /\ ClaimResources(<<Temporary>>)
  /\ state' = WorkspaceAllocated
  /\ UNCHANGED <<released, cleanupOrder, sandboxReady, digestMismatch,
                 noWorkloadEffect, nextAction, liveProcess>>

CreateIsolation ==
  /\ state = WorkspaceAllocated
  /\ ClaimResources(<<Mount, Namespace>>)
  /\ state' = IsolationCreated
  /\ UNCHANGED <<released, cleanupOrder, sandboxReady, digestMismatch,
                 noWorkloadEffect, nextAction, liveProcess>>

AttachResources ==
  /\ state = IsolationCreated
  /\ ClaimResources(<<Cgroup, Pidfd>>)
  /\ state' = ResourcesAttached
  /\ UNCHANGED <<released, cleanupOrder, sandboxReady, digestMismatch,
                 noWorkloadEffect, nextAction, liveProcess>>

CloseWorkloadGate ==
  /\ state = ResourcesAttached
  /\ state' = WorkloadStopped
  /\ sandboxReady' = TRUE
  /\ noWorkloadEffect' = TRUE
  /\ liveProcess' = FALSE
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 digestMismatch, nextAction>>

(* The gate can open only after all six resources are owned, the digest is
   known good, and no workload instruction has been observed. *)
ReleaseGate ==
  /\ state = WorkloadStopped
  /\ ~digestMismatch
  /\ sandboxReady = TRUE
  /\ noWorkloadEffect = TRUE
  /\ ~liveProcess
  /\ ClaimResources(<<Process>>)
  /\ state' = Running
  /\ sandboxReady' = TRUE
  /\ liveProcess' = TRUE
  /\ noWorkloadEffect' = FALSE
  /\ UNCHANGED <<released, cleanupOrder, digestMismatch, nextAction>>

BeginStopping ==
  /\ state = Running
  /\ ~noWorkloadEffect
  /\ state' = Stopping
  /\ liveProcess' = FALSE
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, nextAction>>

ConfirmStopped ==
  /\ state = Stopping
  /\ ~liveProcess
  /\ state' = Stopped
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, nextAction,
                 liveProcess>>

(* Cleanup is reverse acquisition order.  Ownership and the ledger are
   removed atomically, so a lost response cannot expose a released live owner. *)
CleanupOne ==
  /\ state \in {Stopped, RollingBack}
  /\ ~liveProcess
  /\ Len(claimOrder) > 0
  /\ LET resource == claimOrder[Len(claimOrder)] IN
       /\ resource \in ownedResources
       /\ resource \in liveOwner
       /\ liveOwner' = liveOwner \ {resource}
       /\ ownedResources' = ownedResources \ {resource}
       /\ released' = released \cup {resource}
       /\ claimOrder' = SubSeq(claimOrder, 1, Len(claimOrder) - 1)
       /\ cleanupOrder' = Append(cleanupOrder, resource)
  /\ UNCHANGED <<state, acquisitionOrder, claimedResources, sandboxReady,
                digestMismatch, noWorkloadEffect, nextAction, liveProcess>>

FinishRollback ==
  /\ state = RollingBack
  /\ ~liveProcess
  /\ ownedResources = {}
  /\ state' = Stopped
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, nextAction,
                 liveProcess>>

Remove ==
  /\ state = Stopped
  /\ ~liveProcess
  /\ ownedResources = {}
  /\ state' = Removed
  /\ nextAction' = NoAction
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, liveProcess>>

Failure ==
  /\ state \in {WorkspaceAllocated, IsolationCreated, ResourcesAttached,
                WorkloadStopped}
  /\ noWorkloadEffect
  /\ ~liveProcess
  /\ state' = RollingBack
  /\ nextAction' = CleanupOrObserve
  /\ NoWorkloadInstruction
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch>>

Ambiguous ==
  /\ state \in {WorkspaceAllocated, IsolationCreated, ResourcesAttached,
                WorkloadStopped, Running}
  /\ state' = StateUnknown
  /\ nextAction' = CleanupOrObserve
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                acquisitionOrder, cleanupOrder, claimedResources,
                sandboxReady, digestMismatch, noWorkloadEffect, liveProcess>>

ObserveProcess ==
  /\ state = StateUnknown
  /\ nextAction = CleanupOrObserve
  /\ liveProcess' = FALSE
  /\ UNCHANGED <<state, liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, nextAction>>

ReconcileUnknown ==
  /\ state = StateUnknown
  /\ nextAction = CleanupOrObserve
  /\ ~liveProcess
  /\ state' = Stopping
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, nextAction,
                 liveProcess>>

RetryCleanup ==
  /\ state = CleanupPending
  /\ nextAction = CleanupOrObserve
  /\ state' = RollingBack
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, nextAction,
                 liveProcess>>

MarkCleanupPending ==
  /\ state \in {RollingBack, Stopped}
  /\ ~liveProcess
  /\ ownedResources # {}
  /\ state' = CleanupPending
  /\ nextAction' = CleanupOrObserve
  /\ UNCHANGED <<liveOwner, released, ownedResources, claimOrder,
                 acquisitionOrder, cleanupOrder, claimedResources,
                 sandboxReady, digestMismatch, noWorkloadEffect, liveProcess>>

Next ==
  \/ Validate
  \/ PinImage
  \/ RejectDigest
  \/ AllocateWorkspace
  \/ CreateIsolation
  \/ AttachResources
  \/ CloseWorkloadGate
  \/ ReleaseGate
  \/ BeginStopping
  \/ ConfirmStopped
  \/ CleanupOne
  \/ FinishRollback
  \/ Remove
  \/ Failure
  \/ Ambiguous
  \/ ObserveProcess
  \/ ReconcileUnknown
  \/ RetryCleanup
  \/ MarkCleanupPending

(* Progress excludes observation-only and cleanup-deferral actions.  Weak
   fairness therefore forces an enabled cleanup/progress action to occur and
   rules out an infinite observation or retry-free stuttering behavior. *)
Progress ==
  \/ Validate
  \/ PinImage
  \/ RejectDigest
  \/ AllocateWorkspace
  \/ CreateIsolation
  \/ AttachResources
  \/ CloseWorkloadGate
  \/ ReleaseGate
  \/ BeginStopping
  \/ ConfirmStopped
  \/ CleanupOne
  \/ FinishRollback
  \/ Remove
  \/ Failure
  \/ Ambiguous
  \/ ObserveProcess
  \/ ReconcileUnknown
  \/ RetryCleanup

Spec == Init /\ [][Next]_vars
  /\ WF_vars(Progress)
  /\ SF_vars(CleanupOne)
  /\ SF_vars(FinishRollback)
  /\ SF_vars(Remove)
  /\ SF_vars(ReconcileUnknown)
  /\ SF_vars(RetryCleanup)

EventuallyStoppedOrRemoved ==
  <> (state = Stopped \/ state = Removed)

=============================================================================
