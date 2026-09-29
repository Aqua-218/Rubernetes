-------------------------------- MODULE Raft --------------------------------

(*
 * M5 Raft consensus model (spec/control-plane/raft.md, spec/verification/formal-methods.md 7.2).
 *
 * The model follows Diego Ongaro's Raft TLA+ specification: servers hold a
 * persistent currentTerm/votedFor/log, messages are sent through an
 * unordered multiset that can duplicate and drop, and the only mutation of a
 * committed entry is forbidden by the invariants below.  Client requests are
 * modelled as values drawn from Clients x request sequence numbers so
 * StateMachineSafety can compare applied prefixes.
 *
 * Bounds required by the specification for the release gate:
 *   Server = 3 nodes, terms 0..4, log length 0..5, 2 clients.
 * The .cfg binds these exactly; the TLC state constraint prunes states that
 * exceed MaxTerm/MaxLogLen so the exploration is finite.
 *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS Server, Clients, MaxTerm, MaxLogLen, MaxRequests

Nil == "Nil"
Follower == "Follower"
Candidate == "Candidate"
Leader == "Leader"

RequestVoteRequest == "RequestVoteRequest"
RequestVoteResponse == "RequestVoteResponse"
AppendEntriesRequest == "AppendEntriesRequest"
AppendEntriesResponse == "AppendEntriesResponse"

Values == Clients \X (1..MaxRequests)

VARIABLES
  messages,       \* multiset of in-flight messages (function msg -> count)
  currentTerm,
  state,
  votedFor,
  log,
  commitIndex,
  votesGranted,
  nextIndex,
  matchIndex,
  requested,      \* set of values already proposed (each value proposed once)
  elections,      \* history: successful elections {term, leader, log}
  allLogs         \* history: every log ever held (for LeaderAppendOnly/LogMatching)

serverVars == <<currentTerm, state, votedFor>>
logVars == <<log, commitIndex>>
candidateVars == <<votesGranted>>
leaderVars == <<nextIndex, matchIndex>>
historyVars == <<elections, allLogs, requested>>
vars == <<messages, serverVars, candidateVars, leaderVars, logVars, historyVars>>

----
\* Helpers

Quorum == {i \in SUBSET(Server) : Cardinality(i) * 2 > Cardinality(Server)}

LastTerm(xlog) == IF Len(xlog) = 0 THEN 0 ELSE xlog[Len(xlog)].term

WithMessage(m, msgs) ==
  IF m \in DOMAIN msgs THEN [msgs EXCEPT ![m] = msgs[m] + 1] ELSE msgs @@ (m :> 1)

WithoutMessage(m, msgs) ==
  IF m \in DOMAIN msgs THEN
    IF msgs[m] <= 1 THEN [x \in DOMAIN msgs \ {m} |-> msgs[x]] ELSE [msgs EXCEPT ![m] = msgs[m] - 1]
  ELSE msgs

Send(m) == messages' = WithMessage(m, messages)
Discard(m) == messages' = WithoutMessage(m, messages)
Reply(response, request) == messages' = WithoutMessage(request, WithMessage(response, messages))

Min(s) == CHOOSE x \in s : \A y \in s : x <= y
Max(s) == CHOOSE x \in s : \A y \in s : x >= y

----
\* Initial state

InitHistoryVars ==
  /\ elections = {}
  /\ allLogs = {}
  /\ requested = {}
InitServerVars ==
  /\ currentTerm = [i \in Server |-> 0]
  /\ state = [i \in Server |-> Follower]
  /\ votedFor = [i \in Server |-> Nil]
InitCandidateVars == votesGranted = [i \in Server |-> {}]
InitLeaderVars ==
  /\ nextIndex = [i \in Server |-> [j \in Server |-> 1]]
  /\ matchIndex = [i \in Server |-> [j \in Server |-> 0]]
InitLogVars ==
  /\ log = [i \in Server |-> << >>]
  /\ commitIndex = [i \in Server |-> 0]
Init ==
  /\ messages = [m \in {} |-> 0]
  /\ InitHistoryVars /\ InitServerVars /\ InitCandidateVars /\ InitLeaderVars /\ InitLogVars

----
\* Actions

\* Server i restarts: volatile state is lost, persistent state (term, vote, log) survives.
Restart(i) ==
  /\ state' = [state EXCEPT ![i] = Follower]
  /\ votesGranted' = [votesGranted EXCEPT ![i] = {}]
  /\ nextIndex' = [nextIndex EXCEPT ![i] = [j \in Server |-> 1]]
  /\ matchIndex' = [matchIndex EXCEPT ![i] = [j \in Server |-> 0]]
  /\ commitIndex' = [commitIndex EXCEPT ![i] = 0]
  /\ UNCHANGED <<messages, currentTerm, votedFor, log, historyVars>>

\* Server i times out and starts a new election.
Timeout(i) ==
  /\ state[i] \in {Follower, Candidate}
  /\ currentTerm[i] < MaxTerm
  /\ state' = [state EXCEPT ![i] = Candidate]
  /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
  /\ votedFor' = [votedFor EXCEPT ![i] = i]
  /\ votesGranted' = [votesGranted EXCEPT ![i] = {i}]
  /\ UNCHANGED <<messages, leaderVars, logVars, historyVars>>

\* Candidate i sends j a RequestVote request.
RequestVote(i, j) ==
  /\ state[i] = Candidate
  /\ i /= j
  /\ Send([mtype |-> RequestVoteRequest, mterm |-> currentTerm[i],
           mlastLogTerm |-> LastTerm(log[i]), mlastLogIndex |-> Len(log[i]),
           msource |-> i, mdest |-> j])
  /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, historyVars>>

\* Leader i sends j an AppendEntries request containing up to 1 entry.
AppendEntries(i, j) ==
  /\ i /= j
  /\ state[i] = Leader
  /\ LET prevLogIndex == nextIndex[i][j] - 1
         prevLogTerm == IF prevLogIndex > 0 THEN log[i][prevLogIndex].term ELSE 0
         lastEntry == Min({Len(log[i]), nextIndex[i][j]})
         entries == SubSeq(log[i], nextIndex[i][j], lastEntry)
     IN Send([mtype |-> AppendEntriesRequest, mterm |-> currentTerm[i],
              mprevLogIndex |-> prevLogIndex, mprevLogTerm |-> prevLogTerm,
              mentries |-> entries, mcommitIndex |-> Min({commitIndex[i], lastEntry}),
              msource |-> i, mdest |-> j])
  /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, historyVars>>

\* Candidate i transitions to leader.
BecomeLeader(i) ==
  /\ state[i] = Candidate
  /\ votesGranted[i] \in Quorum
  /\ state' = [state EXCEPT ![i] = Leader]
  /\ nextIndex' = [nextIndex EXCEPT ![i] = [j \in Server |-> Len(log[i]) + 1]]
  /\ matchIndex' = [matchIndex EXCEPT ![i] = [j \in Server |-> 0]]
  /\ elections' = elections \cup {[eterm |-> currentTerm[i], eleader |-> i, elog |-> log[i]]}
  /\ UNCHANGED <<messages, currentTerm, votedFor, candidateVars, logVars, allLogs, requested>>

\* Leader i receives a client request to add value v to the log (each value once).
ClientRequest(i, v) ==
  /\ state[i] = Leader
  /\ v \notin requested
  /\ Len(log[i]) < MaxLogLen
  /\ LET entry == [term |-> currentTerm[i], value |-> v]
         newLog == Append(log[i], entry)
     IN /\ log' = [log EXCEPT ![i] = newLog]
        /\ allLogs' = allLogs \cup {newLog}
        /\ requested' = requested \cup {v}
  /\ UNCHANGED <<messages, serverVars, candidateVars, leaderVars, commitIndex, elections>>

\* Leader i advances its commitIndex (section 5.4.2: only current-term entries by counting).
AdvanceCommitIndex(i) ==
  /\ state[i] = Leader
  /\ LET Agree(index) == {i} \cup {k \in Server : matchIndex[i][k] >= index}
         agreeIndexes == {index \in 1..Len(log[i]) : Agree(index) \in Quorum}
         newCommitIndex ==
           IF /\ agreeIndexes /= {}
              /\ log[i][Max(agreeIndexes)].term = currentTerm[i]
           THEN Max(agreeIndexes)
           ELSE commitIndex[i]
     IN commitIndex' = [commitIndex EXCEPT ![i] = newCommitIndex]
  /\ UNCHANGED <<messages, serverVars, candidateVars, leaderVars, log, historyVars>>

----
\* Message handlers

HandleRequestVoteRequest(i, j, m) ==
  LET logOk == \/ m.mlastLogTerm > LastTerm(log[i])
               \/ /\ m.mlastLogTerm = LastTerm(log[i])
                  /\ m.mlastLogIndex >= Len(log[i])
      grant == /\ m.mterm = currentTerm[i]
               /\ logOk
               /\ votedFor[i] \in {Nil, j}
  IN /\ m.mterm <= currentTerm[i]
     /\ \/ grant /\ votedFor' = [votedFor EXCEPT ![i] = j]
        \/ ~grant /\ UNCHANGED votedFor
     /\ Reply([mtype |-> RequestVoteResponse, mterm |-> currentTerm[i], mvoteGranted |-> grant,
               msource |-> i, mdest |-> j], m)
     /\ UNCHANGED <<state, currentTerm, candidateVars, leaderVars, logVars, historyVars>>

HandleRequestVoteResponse(i, j, m) ==
  /\ m.mterm = currentTerm[i]
  /\ \/ /\ m.mvoteGranted
        /\ votesGranted' = [votesGranted EXCEPT ![i] = votesGranted[i] \cup {j}]
     \/ /\ ~m.mvoteGranted
        /\ UNCHANGED votesGranted
  /\ Discard(m)
  /\ UNCHANGED <<serverVars, leaderVars, logVars, historyVars>>

RejectAppendEntriesRequest(i, j, m, logOk) ==
  /\ \/ m.mterm < currentTerm[i]
     \/ /\ m.mterm = currentTerm[i]
        /\ state[i] = Follower
        /\ ~logOk
  /\ Reply([mtype |-> AppendEntriesResponse, mterm |-> currentTerm[i], msuccess |-> FALSE,
            mmatchIndex |-> 0, msource |-> i, mdest |-> j], m)
  /\ UNCHANGED <<serverVars, logVars>>

ReturnToFollowerState(i, m) ==
  /\ m.mterm = currentTerm[i]
  /\ state[i] = Candidate
  /\ state' = [state EXCEPT ![i] = Follower]
  /\ UNCHANGED <<currentTerm, votedFor, logVars, messages>>

AppendEntriesAlreadyDone(i, j, index, m) ==
  /\ \/ m.mentries = << >>
     \/ /\ m.mentries /= << >>
        /\ Len(log[i]) >= index
        /\ log[i][index].term = m.mentries[1].term
  /\ commitIndex' = [commitIndex EXCEPT ![i] = m.mcommitIndex]
  /\ Reply([mtype |-> AppendEntriesResponse, mterm |-> currentTerm[i], msuccess |-> TRUE,
            mmatchIndex |-> m.mprevLogIndex + Len(m.mentries), msource |-> i, mdest |-> j], m)
  /\ UNCHANGED <<serverVars, log>>

ConflictAppendEntriesRequest(i, index, m) ==
  /\ m.mentries /= << >>
  /\ Len(log[i]) >= index
  /\ log[i][index].term /= m.mentries[1].term
  /\ LET new == [index2 \in 1..(Len(log[i]) - 1) |-> log[i][index2]]
     IN log' = [log EXCEPT ![i] = new]
  /\ UNCHANGED <<serverVars, commitIndex, messages>>

NoConflictAppendEntriesRequest(i, m) ==
  /\ m.mentries /= << >>
  /\ Len(log[i]) = m.mprevLogIndex
  /\ log' = [log EXCEPT ![i] = Append(log[i], m.mentries[1])]
  /\ UNCHANGED <<serverVars, commitIndex, messages>>

AcceptAppendEntriesRequest(i, j, logOk, m) ==
  LET index == m.mprevLogIndex + 1
  IN /\ m.mterm = currentTerm[i]
     /\ state[i] = Follower
     /\ logOk
     /\ \/ AppendEntriesAlreadyDone(i, j, index, m)
        \/ ConflictAppendEntriesRequest(i, index, m)
        \/ NoConflictAppendEntriesRequest(i, m)

HandleAppendEntriesRequest(i, j, m) ==
  LET logOk == \/ m.mprevLogIndex = 0
               \/ /\ m.mprevLogIndex > 0
                  /\ m.mprevLogIndex <= Len(log[i])
                  /\ m.mprevLogTerm = log[i][m.mprevLogIndex].term
  IN /\ m.mterm <= currentTerm[i]
     /\ \/ RejectAppendEntriesRequest(i, j, m, logOk)
        \/ ReturnToFollowerState(i, m)
        \/ AcceptAppendEntriesRequest(i, j, logOk, m)
     /\ UNCHANGED <<candidateVars, leaderVars, historyVars>>

HandleAppendEntriesResponse(i, j, m) ==
  /\ m.mterm = currentTerm[i]
  /\ \/ /\ m.msuccess
        /\ nextIndex' = [nextIndex EXCEPT ![i][j] = m.mmatchIndex + 1]
        /\ matchIndex' = [matchIndex EXCEPT ![i][j] = m.mmatchIndex]
     \/ /\ ~m.msuccess
        /\ nextIndex' = [nextIndex EXCEPT ![i][j] = Max({nextIndex[i][j] - 1, 1})]
        /\ UNCHANGED matchIndex
  /\ Discard(m)
  /\ UNCHANGED <<serverVars, candidateVars, logVars, historyVars>>

\* Any RPC with a newer term causes the recipient to advance its term first.
UpdateTerm(i, j, m) ==
  /\ m.mterm > currentTerm[i]
  /\ currentTerm' = [currentTerm EXCEPT ![i] = m.mterm]
  /\ state' = [state EXCEPT ![i] = Follower]
  /\ votedFor' = [votedFor EXCEPT ![i] = Nil]
  /\ UNCHANGED <<messages, candidateVars, leaderVars, logVars, historyVars>>

DropStaleResponse(i, j, m) ==
  /\ m.mterm < currentTerm[i]
  /\ Discard(m)
  /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, historyVars>>

Receive(m) ==
  LET i == m.mdest
      j == m.msource
  IN \/ UpdateTerm(i, j, m)
     \/ /\ m.mtype = RequestVoteRequest
        /\ HandleRequestVoteRequest(i, j, m)
     \/ /\ m.mtype = RequestVoteResponse
        /\ \/ DropStaleResponse(i, j, m)
           \/ HandleRequestVoteResponse(i, j, m)
     \/ /\ m.mtype = AppendEntriesRequest
        /\ HandleAppendEntriesRequest(i, j, m)
     \/ /\ m.mtype = AppendEntriesResponse
        /\ \/ DropStaleResponse(i, j, m)
           \/ HandleAppendEntriesResponse(i, j, m)

\* Network faults: duplication and loss.
DuplicateMessage(m) ==
  /\ Send(m)
  /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, historyVars>>

DropMessage(m) ==
  /\ Discard(m)
  /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, historyVars>>

----

Next ==
  \/ \E i \in Server : Restart(i)
  \/ \E i \in Server : Timeout(i)
  \/ \E i, j \in Server : RequestVote(i, j)
  \/ \E i \in Server : BecomeLeader(i)
  \/ \E i \in Server, v \in Values : ClientRequest(i, v)
  \/ \E i \in Server : AdvanceCommitIndex(i)
  \/ \E i, j \in Server : AppendEntries(i, j)
  \/ \E m \in DOMAIN messages : Receive(m)
  \/ \E m \in DOMAIN messages : DuplicateMessage(m)
  \/ \E m \in DOMAIN messages : DropMessage(m)

Spec == Init /\ [][Next]_vars

----
\* Bounds for TLC (recorded in Raft.cfg as CONSTRAINT)

StateConstraint ==
  /\ \A i \in Server : currentTerm[i] <= MaxTerm
  /\ \A i \in Server : Len(log[i]) <= MaxLogLen
  /\ \A m \in DOMAIN messages : messages[m] <= 2

----
\* Invariants (spec 7.2)

TypeOK ==
  /\ \A i \in Server : currentTerm[i] \in 0..MaxTerm
  /\ \A i \in Server : state[i] \in {Follower, Candidate, Leader}
  /\ \A i \in Server : votedFor[i] \in Server \cup {Nil}
  /\ \A i \in Server : commitIndex[i] \in 0..MaxLogLen
  /\ \A i \in Server : Len(log[i]) <= MaxLogLen

\* At most one leader per term.
ElectionSafety ==
  \A i, j \in Server :
    (state[i] = Leader /\ state[j] = Leader /\ currentTerm[i] = currentTerm[j]) => i = j

\* A leader's log only grows while it is leader (checked against the election history).
LeaderAppendOnly ==
  \A e \in elections :
    (state[e.eleader] = Leader /\ currentTerm[e.eleader] = e.eterm) =>
      /\ Len(log[e.eleader]) >= Len(e.elog)
      /\ \A idx \in 1..Len(e.elog) : log[e.eleader][idx] = e.elog[idx]

\* If two logs contain an entry with the same index and term, the logs are identical up to that index.
LogMatching ==
  \A i, j \in Server :
    \A n \in 1..Min({Len(log[i]), Len(log[j])}) :
      log[i][n].term = log[j][n].term =>
        \A m \in 1..n : log[i][m] = log[j][m]

\* Every entry committed on some server is present in the log of every leader of a later term.
Committed(i, idx) == idx <= commitIndex[i]
LeaderCompleteness ==
  \A i \in Server : \A idx \in 1..Len(log[i]) :
    Committed(i, idx) =>
      \A e \in elections :
        e.eterm > log[i][idx].term =>
          /\ Len(e.elog) >= idx
          /\ e.elog[idx] = log[i][idx]

\* Applied (committed) prefixes never disagree.
StateMachineSafety ==
  \A i, j \in Server :
    \A idx \in 1..Min({commitIndex[i], commitIndex[j]}) :
      log[i][idx] = log[j][idx]

\* A committed entry is present in a quorum of logs.
CommittedInQuorum ==
  \A i \in Server : \A idx \in 1..commitIndex[i] :
    {k \in Server : Len(log[k]) >= idx /\ log[k][idx] = log[i][idx]} \in Quorum

=============================================================================
