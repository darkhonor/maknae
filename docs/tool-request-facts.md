# Tool request facts

A `tool.invoke` request carries a fixed set of resource facts. They are the contract between the trust plane, which stamps them, and any authorization engine that decides the request. `maknae-authz-basic` is one such engine; an engine with richer selection (for example one backed by a data-classification product) decides on the same facts. The constants live in `crates/maknae-security/src/request.rs`.

Every fact is stamped by the kernel from its own rendering of the call and from the cited task's sealed record. None is copied from a client-supplied field. A client names an entry, a program, a shape and slot values; the kernel resolves and renders them, then stamps what it rendered.

## Resource facts

| Fact | Type | Present when | Filled from | Read by `-basic` |
|---|---|---|---|---|
| `tool.entry` | `Str` | always | the `tools.yaml` entry the call names | yes |
| `tool.program` | `Str` | always | the program within that entry | yes |
| `tool.mode` | `Str`: `shape`, `open` or `positional` | always | the command's form in the entry (a grammar command is `shape`, `open: true` is `open`, `subcommands` is `positional`) | yes |
| `tool.shape` | `Str` | shape mode | the shape name the call selected | yes |
| `tool.class` | `Str`: `read` or `write` | shape mode | the shape's declared class | no |
| `tool.argv` | `List` (ordered) | always | the final argv: rendered from the shape template in shape mode, as given in open and positional mode | yes |
| `tool.stdin.sha256` | `Str` (lowercase hex) | shape mode, when the shape has a `stdin` slot | SHA-256 of the stdin bytes | no |
| `tool.files.sha256` | `List` | shape mode, when the shape has `file` slots | SHA-256 of each file slot's content, in slot-name order | no |
| `tool.forge.base` | `Set` of forge operations | shape mode | the shape's declared `forge.base` operations | no |
| `tool.forge.head` | `Set` of forge operations | shape mode | the shape's declared `forge.head` operations | no |
| `tool.binding` | `Int` | shape mode, when the task has a git binding | the index of the selected binding in the task's bindings | no |
| `binding.kinds` | `Set` | always (empty with no task or no binding) | the kinds of the task's bindings | yes |
| `bound.git.server`, `bound.git.base`, `bound.git.head`, `bound.git.change` | `List` each, index-aligned | the task has a git binding | the bindings' sealed values; `""` marks an absent `head` or `change` | yes |
| `reach.git.base` | `Set` of forge operations | the task has a git binding | the binding's sealed effective reach on the base repository | no |
| `reach.git.head` | `Set` of forge operations | the task has a git binding | the binding's sealed effective reach on the head repository | no |
| `tool.labels` | `Set` | always | empty; reserved for a labeling engine | no |

Forge operations are spelled as on the wire: `read`, `review`, `issue-write`, `push-head`, `merge`.

A shape call is rendered against exactly one binding: the task's only git binding, or the one the call selects by index. For a shape call, `binding.kinds`, `bound.git.*` and `reach.git.*` describe that binding alone. Open and positional calls carry every binding of the task.

`tool.labels` is stamped as an empty set. A labeling engine fills it later; an engine that reads it today sees no labels, never an absent fact.

The subject facts are the ones every request carries: `uid`, `home`, the channel, the agent, `task` and the tasker. The role is resolved by the engine from the subject.

## What `-basic` decides on

`-basic` reads `tool.entry`, `tool.program`, `tool.mode`, `tool.shape`, `tool.argv`, `binding.kinds` and `bound.git.*`. The other facts are for other engines.

Its ceiling, in order:

1. `tool.entry`, `tool.program`, `tool.argv` and `tool.mode` must be present with their types, or the request is Indeterminate. A `tool.mode` outside the three values is Indeterminate.
2. The entry must be enabled in `tools.yaml` and must hold the program.
3. `tool.mode` must match the command's form, or the request is denied.
4. By mode:
   - **shape:** `tool.shape` must be present (Indeterminate otherwise) and enabled for the command. The call may carry at most one git binding. `tool.argv` must be exactly what the shape's template produces for that binding: equal literals, bound tokens equal to the bound values, slot tokens passing their constraints. A template changed by a reload no longer matches an argv rendered from the old one.
   - **positional:** `tool.argv` must match one of the command's `subcommands` patterns.
   - **open:** `tool.argv` must pass the open-mode lexical checks (token count, token length, no NUL or control characters).
5. No `deny_args` pattern may match any argument of `tool.argv`, in every mode.
6. Every binding kind the entry requires must be in `binding.kinds`.

Past the ceiling, grants decide: `Tool(<entry> <program>:<shape pattern>)` matches shape calls only, and `Tool(<entry> <program> <argv pattern>)` matches open and positional calls only.

## Changing the contract

Adding a fact is additive: engines that do not read it are unaffected. Renaming or removing a fact, or changing its type or its values, is a contract change under ADR-0004 and needs the same review as a change to the `Authorizer` interface.
