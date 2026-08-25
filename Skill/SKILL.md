---
name: code-doc-comments
description: Writes and standardizes documentation comments on methods, functions, classes, and scripts — X++ (Dynamics 365 F&O / Dynamics AX) XML doc comments and PowerShell comment-based help today, more languages as they're added. Use this whenever the user asks to document, comment, add doc headers/summaries to, or clean up/standardize documentation on code in a covered language — including when they just paste code and ask for documentation without naming the format, or ask to make a file's comments consistent.
---

# Code Documentation Comments

This skill documents code in the house style for whichever language it's written in. Each language has its own doc-comment convention (tags, section names, placement), so the process is: figure out the language, load that language's reference, then apply it.

## Step 1: Identify the language

Usually obvious from a file extension, a code fence's language tag, or the syntax itself (X++ reads like C# with `str`/`container`/`;`-terminated declarations inside `class`/`public` blocks; PowerShell has `$variables`, `param()`, `function Verb-Noun`). If genuinely ambiguous, ask rather than guess — applying the wrong doc convention is worse than a clarifying question.

## Step 2: Load the matching reference

| Language | Reference |
|---|---|
| X++ / Dynamics 365 F&O / Dynamics AX | `references/xpp.md` |
| PowerShell | `references/powershell.md` |

Read the relevant file before writing any documentation — it has the exact template, formatting rules, and worked examples for that language. Don't rely on general knowledge of "XML doc comments" or "PowerShell help" instead of the reference; the reference encodes this user's specific conventions and edge-case handling.

If the user asks for a language that isn't in the table yet, say so, apply general best practice for that language's standard doc-comment convention (e.g. Python docstrings, Java/C# XML docs, JSDoc), and mention that you could add a proper reference for it if they'll be doing this often.

## Shared principles across every language

These apply regardless of which reference you load:

- **Describe behavior, not the signature.** Read the body, not just the name/parameters, and say what the code actually does — what it queries, computes, mutates, or has as a side effect. Don't just reword the method name.
- **Don't pad.** Omit optional sections that don't apply (e.g. a parameters section for a parameter-less function) rather than leaving them empty. Keep required sections concise — a sentence or two is usually enough.
- **Match existing formatting conventions** (indentation, blank-line spacing) from the surrounding code.
- **When fixing/standardizing existing docs:** reformat to the correct structure even if the wording is fine, add any tag/section that's missing, and correct descriptions that are stale relative to current behavior — but flag non-obvious corrections to the user, since you're inferring intent from code. Only touch the doc comment block itself; leave attributes, decorators, and surrounding code untouched. Skip members that are already complete and correctly formatted unless the user asked for a full standardization pass.
- **Document everything**, not just the public surface — internal/private helpers get documented too, following the same convention.

See the per-language reference for the exact template and worked examples before producing output.
