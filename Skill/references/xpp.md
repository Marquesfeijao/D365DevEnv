# X++ (Dynamics 365 F&O / Dynamics AX) Documentation Comments

X++ doc comments follow a specific multi-line XML convention (matching the style Microsoft's own D365 F&O codebase uses). Every tag's content goes on its own line — never inline with the opening/closing tag — and indentation matches the member it documents.

## Method template

```xpp
    /// <summary>
    /// [One or more sentences describing what the method does, in plain functional terms.]
    /// </summary>
    /// <param name="_paramName">
    /// [Description of the parameter.]
    /// </param>
    /// <returns>
    /// [Description of what is returned.]
    /// </returns>
```

Rules:
- One `<param>` block per parameter, in declaration order, using the exact parameter name (including the `_` prefix).
- **Omit the `<param>` block entirely** for a parameter-less method — don't leave an empty one.
- **Omit the `<returns>` block entirely** for `void` methods and constructors — don't leave an empty one.
- Tag content is indented one level deeper than the tag itself and sits on its own line(s).
- The doc comment's indentation matches the method signature that follows it.

## Class template

```xpp
/// <summary>
/// [What the class represents or is responsible for, in plain terms.]
/// </summary>
class ClassName
{
}
```

- Classes only get a `<summary>` — there's no `<param>`/`<returns>` equivalent.
- Add a `<remarks>` block after `</summary>` only if there's genuinely important extra context (e.g. usage caveats, threading notes). Don't pad a doc comment with a remarks block that just repeats the summary.

## Writing good summaries, not boilerplate

- Describe what the code *does*, in behavioral terms — "Finds or creates dynamic dimension account combining account and dimensions," not "Gets the account."
- Read the method body, not just the signature, to figure out real behavior: what it queries, computes, validates, or has side effects on. Mention this if it's non-obvious.
- Don't restate the parameter name in the summary — that's what `<param>` is for.
- For classes, describe the responsibility of the class, not a restatement of its name.
- Keep summaries to 1–3 sentences. Terse is fine as long as it's accurate and specific.

## Fixing or standardizing existing doc comments

This skill is just as often used to clean up docs that already exist but don't match the pattern (single-line comments, missing tags, stale descriptions). When doing this:

- Reformat any single-line or inline doc comment (e.g. `/// <summary>Does X</summary>`) into the multi-line form, even if the wording itself is fine.
- Add any tag that's missing but should exist (e.g. a parameter was added later and never documented).
- If a description looks stale or inaccurate relative to what the code actually does now, correct it — but call out non-obvious corrections in your reply so the user can confirm you read the intent correctly, since you're inferring behavior from code.
- Only touch the `///` comment block immediately preceding a declaration. Leave attributes, decorators, and surrounding code untouched.
- Skip members that already have complete, correctly-formatted docs, unless the user's ask is specifically to review/standardize the whole file.

## Applying across a file

- Work top to bottom in file order.
- Document every method regardless of access modifier (`public`, `protected`, `private`) — X++ convention documents internal helpers too, not just the public surface.
- For heavily overloaded methods, document each overload individually — their behavior or parameters usually differ enough to warrant it.

## Examples

**Undocumented method:**
```xpp
public AccountNum findOrCreateDynamicAccount(AccountNum _account, DimensionDynamic _dimensions)
{
    ...
}
```
→
```xpp
    /// <summary>
    /// Finds or creates dynamic dimension account combining account and dimensions.
    /// </summary>
    /// <param name="_account">
    /// The account to be combined.
    /// </param>
    /// <param name="_dimensions">
    /// The dimensions to be combined.
    /// </param>
    /// <returns>
    /// The dynamic dimension account.
    /// </returns>
    public AccountNum findOrCreateDynamicAccount(AccountNum _account, DimensionDynamic _dimensions)
    {
        ...
    }
```

**Void method, no parameters** (both blocks omitted):
```xpp
    /// <summary>
    /// Clears the cached dimension lookup results.
    /// </summary>
    void clearCache()
    {
        ...
    }
```

**Standardizing an inconsistent inline comment:**
```xpp
/// <summary>Validates the account.</summary>
public boolean isValid(AccountNum _account)
{
    ...
}
```
→
```xpp
    /// <summary>
    /// Validates the account.
    /// </summary>
    /// <param name="_account">
    /// The account to validate.
    /// </param>
    /// <returns>
    /// True if the account is valid; otherwise, false.
    /// </returns>
    public boolean isValid(AccountNum _account)
    {
        ...
    }
```

**Class:**
```xpp
/// <summary>
/// Provides helper methods for finding and creating dynamic dimension accounts.
/// </summary>
class DimensionAccountHelper
{
}
```
