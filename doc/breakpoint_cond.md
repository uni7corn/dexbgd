# Conditional Breakpoints

## Syntax

```
bp <class> <method> [--hits N] [--every N] [--when <expr>]
bp-<profile> [--hits N] [--every N] [--when <expr>]
```

## Flags

| Flag | Description |
|------|-------------|
| `--hits N` | Break on the Nth hit only (then never again) |
| `--every N` | Break every Nth hit (skip the rest) |
| `--when <expr>` | Break only when expression is true |

## Expression syntax

```
<lhs> <op> <rhs>
```

**Operands:**

| Value | Description |
|-------|-------------|
| `v0`, `v1`, `v2` | Register slots (Dalvik numbering) |
| `varname` | Named local variable (or bare string if not found) |
| `"string"` / `'string'` | String literal |
| `42`, `-1` | Integer literal |
| `null` | Null value |

**Operators:**

| Op | Meaning |
|----|---------|
| `==` | equal |
| `!=` | not equal |
| `~` | contains (string substring match) |
| `<` | less than |
| `>` | greater than |
| `<=` | less or equal |
| `>=` | greater or equal |

## Dalvik register layout (instance methods)

```
v0 = this
v1 = first arg
v2 = second arg
...
```

This assumes no extra local variables. Use the `locals` command after hitting a plain breakpoint to see what registers are actually available before adding conditions.

## Examples

```
# Break only on AES encryption (ENCRYPT_MODE = 1)
bp javax.crypto.Cipher init --when v1 == 1

# Break only on AES decryption (DECRYPT_MODE = 2)
bp javax.crypto.Cipher init --when v1 == 2

# Break when URL contains "evil"
bp java.net.URL <init> --when v1 ~ evil

# Break when URL contains a specific word (quoted)
bp java.net.URL <init> --when v1 ~ 'malware'

# Skip first 5 hits, break on 6th
bp javax.crypto.Cipher doFinal --hits 6

# Break every 3rd hit (useful for noisy APIs)
bp javax.crypto.Cipher doFinal --every 3

# Combined: every 2nd hit, but only encryption mode
bp javax.crypto.Cipher init --every 2 --when v1 == 1

# Breakpoint profiles with conditions
bp-crypto --every 5
bp-network --when v1 ~ evil
bp-exec --hits 1

# Named locals (works when debug info is available, e.g. app code)
bp com.example.MainActivity testCrypto --when aesKey != null

# Numeric comparison on register
bp javax.crypto.KeyGenerator init --when v1 >= 256
```

## Quoting rules

No quotes needed around a `--when` expression. Quotes are optional and all of these are equivalent:

```
bp javax.crypto.Cipher init --when v1 == 1
bp javax.crypto.Cipher init --when "v1 == 1"
```

For string values inside a double-quoted expression, use single quotes:

```
bp java.net.URL <init> --when "v1 ~ 'evil'"
```

Or just use bare words — unquoted strings that are not local variable names become string literals:

```
bp java.net.URL <init> --when v1 ~ evil
```

## Notes

- Conditions are evaluated server-side — no agent changes needed
- For framework classes (Cipher, URL, etc.) locals show as `v0`, `v1`, `v2` because framework bytecode has no debug info
- For app classes, locals show real names (`aesKey`, `cipher`, etc.)
- Use `locals` after a plain breakpoint to see what is available, then add a condition
- When no method signature is specified, breakpoints are set on all overloads of that method name
- `bd *` clears all breakpoints and resets condition state
- Hit counts are shown in the BP panel: `#1 Cipher.init [every=3] (5x)`
