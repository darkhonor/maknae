# Kernel notices: the kernel as a writer, never a reader

**Status:** Exploratory idea. This is not an ADR, a specification or an implementation plan, and nothing here is built.

**Origin:** Maintainer, 2026-11-25, during the agent message board work (epic #693, [ADR-0040](../adr/ADR-0040-the-agent-message-board.md)).

## The idea, in the maintainer's words

> Part of the idea, and it may have been scoped out previously, so I might be off here. Was to have the Kernel be able to notify agents, users, other components of things. Not a reader. Only a writer.

> I would like a way for the kernel to communicate with components, agents, and users. Post only; no read--in order to prevent possible injection attack against the kernel. Can be proxied as necessary to ensure the TCB is secure. Open for ideas, message types, etc.

## Why it is worth having

Today the kernel answers the request in front of it and writes the audit trail. A person who tasks agents cannot read the audit trail, and an agent learns of a kernel-side event only when its next request is refused. Things happen that the people and programs around the kernel would act on if they knew: a policy reload, a board switched off, a record quarantined at start, a credential about to expire. A notice is how the kernel says so without anyone having to ask.

## The one rule: post only

The kernel writes notices and reads nothing back. No reply, no acknowledgement text, no thread. A notice channel that carried anything back would be a second input to the reference monitor, and its content would come from the untrusted side.

What follows from that rule:

- **A notice is never a request.** It informs and never authorizes, the same rule the board's posts follow. An agent that receives a notice gains no permission from it.
- **Delivery status is the most the kernel may learn**, and perhaps not even that. "Written to the outbox" is a fact the kernel already has. "The user saw it" is a claim from outside; if it is ever recorded, it is recorded by the component that observed it, not consumed by the kernel.
- **The kernel's voice is the most trusted voice a model will hear, so nothing untrusted may speak through it.** A notice is built from a closed set of kinds with fixed wording and kernel-derived fields (ids, names the kernel validated, counts, times, enum values). It never carries text an agent, a tool or retrieved content supplied. Otherwise an agent could provoke a notice that repeats its own words to another agent in the kernel's name.
- **The author stamp cannot be forged.** Only the kernel can produce a notice; no channel lets an agent or a client post as the kernel.

## Possible shape

These are options to weigh, not a design.

1. **An outbox the kernel only appends to.** The kernel writes each notice as a record (through `maknae-io`, like every other file it writes) and never opens the outbox for reading. Everything downstream reads the outbox; nothing downstream can write where the kernel reads.
2. **A notifier outside the TCB as the proxy.** A small, unprivileged component reads the outbox and delivers: to the `maknae` CLI when a user next runs it, to a watching terminal, to the system journal for operators, and later to mail or a webhook if a site wants them. All the parsing, formatting, retrying and network code lives there. If the notifier is compromised, notices can be lost or delayed; the kernel is not reached, because the flow is one way.
3. **Agents receive notices through the surface they already read.** The board is the obvious carrier: #719 leaves `Author` as an enum with one variant, `Agent`, so a `Kernel` author is an additive variant later. A kernel-authored post would be addressed to the board or to named agents and decided per reader like any other post. The kernel would write it and still never read the board for its own decisions.
4. **Components get typed events, not prose.** The Egress Daemon and the Agent Daemon would receive the same closed set of kinds as structured records, so no component parses a sentence.

## Who may see a notice

A notice can disclose something by existing (that a path is on the sensitive list, that another person's agent was refused). So each notice would carry a recipient and labels, and its release to that recipient would be decided through the composition like any other read. An administrator's notice about a quarantined record and a tasker's notice about their own agent are different audiences and are never merged into one feed.

## Message kinds to consider

To people who task agents:

- an agent of theirs finished, failed, or stopped responding;
- a request from their agent was refused, with the operand's own refusal line and nothing more;
- their board was switched on or off, cleared, or reached its cap;
- a post on their board is held or was withheld from a reader;
- their credential or login is close to expiry.

To agents:

- the policy changed during the task, try again;
- the board for this task was switched off;
- the task was cancelled, or its tasker's session ended;
- a limit is close (posts, read rounds, time).

To administrators and operators:

- records quarantined at start, with their findings;
- a policy, principal or `sensitive.yaml` reload: applied, or refused and why;
- a start refused, and the remedy;
- repeated refusals from one agent or one user (a pattern worth a look);
- audit sink trouble, disk pressure in the state directory;
- certificate and key rotation due.

To components:

- configuration reloaded, shutting down, draining;
- a principal or agent was removed, drop its sessions.

## Things to keep out

- A reply path of any kind, including "acknowledge to dismiss" handled by the kernel.
- Free text from any untrusted source inside a notice.
- Notices as a control channel: nothing acts on a notice with authority it did not already have.
- A second audit trail. The audit trail stays the record; a notice is a courtesy copy of selected events for someone who cannot read the trail, and a lost notice loses nothing from the record.

## Open questions

- Is the outbox one store or one per audience (person, administrator, component)?
- Does a kernel-authored board post count against the board's caps and retention, or sit beside them?
- Which kinds are on by default? The board's own switches are all default-off; notices to administrators arguably should not be.
- How long is an undelivered notice kept, and who clears it?
- What stops a hostile agent from flooding a person with refusal notices? Per-kind rate limits and collapsing repeats ("refused 40 times") are the usual answers.
- How does a terminal display a notice safely? Kernel-derived fields still include names; the escaping problem in #716 applies here too.
- Does the reporting planned in #715 (`report`, `maknae board watch`) become one consumer of this, or stay its own thing?
