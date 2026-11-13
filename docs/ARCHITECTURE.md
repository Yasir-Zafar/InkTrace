# InkTrace Architecture

> Draft. Sections get filled in as each part is built.

## Overview

InkTrace hides a signed, per-recipient code inside plain text using zero-width Unicode characters,
and later reads it back from a leaked copy to find out whose copy it was.

## Components

- `zw`: converts bits to and from zero-width characters
- `crypto`: key generation and loading, HMAC-SHA256 tags
- `payload`: packs `version | doc_id | recipient_id | tag` and frames it
- `embed`: places frames in the text without changing what is visible
- `trace`: finds frames in a leaked text, checks tags, decides the outcome
- `store`: SQLite database of documents, recipients and issued copies
- `cli` / `web`: command-line tool and demo web page

## Design

### Zero-width alphabet

| Char | Code point | Role |
|---|---|---|
| ZERO WIDTH SPACE | U+200B | bit `0` |
| ZERO WIDTH NON-JOINER | U+200C | bit `1` |
| WORD JOINER | U+2060 | frame start / end |

One bit per character. It is longer than a 4-symbol alphabet, but it keeps parsing simple and
does not use U+200D (ZWJ), which changes how emoji render. U+FEFF is not used because many tools
strip it as a byte order mark.

### Payload format

116 bits, big-endian:

| Field | Bits | Notes |
|---|---|---|
| `version` | 4 | `1` for now |
| `doc_id` | 32 | document id |
| `recipient_id` | 16 | recipient id within the document |
| `tag` | 64 | truncated HMAC, see below |

A frame is `U+2060 + 116 data chars + U+2060`, so 118 invisible characters.

### Key handling

- Master key `K`: 32 random bytes from `secrets.token_bytes`, kept by the sender only (file or `INKTRACE_KEY`).
- Per-document key: `K_doc = HMAC-SHA256(K, "inktrace-doc" || doc_id)`.
- Tag: `HMAC-SHA256(K_doc, "inktrace-v1" || version || doc_id || recipient_id)`, first 8 bytes.
  `version` is 1 byte, `doc_id` 4 bytes, `recipient_id` 2 bytes, all big-endian.
- Tags are compared with `hmac.compare_digest`.

A 64-bit tag means a random guess passes with probability 2^-64. An attacker cannot test guesses
offline because they do not have `K`, so this is enough for our use.

### Placement in the text

### Trace outcomes

## Data flow

### Embedding a document

### Tracing a leaked copy

## Database schema

## Design decisions and alternatives
