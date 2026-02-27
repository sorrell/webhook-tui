# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Add Raw Body Toggle & Copy to Details View

## Context
The details view currently shows the request body as pretty-printed JSON (when parseable) or raw text. We need to add:
1. A toggle to switch between pretty-printed and raw body display
2. A keybinding to copy the raw request body to the clipboard

## Changes — `/Users/sorrell/src/tools/webhook-tui/main.go`

### 1. Add `showRawBody` field to `Model` struct (~line 183)
- Add `showRawBody bool` field to track ...

