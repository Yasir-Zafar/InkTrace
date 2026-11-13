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

### Key handling

### Placement in the text

### Trace outcomes

## Data flow

### Embedding a document

### Tracing a leaked copy

## Database schema

## Design decisions and alternatives
