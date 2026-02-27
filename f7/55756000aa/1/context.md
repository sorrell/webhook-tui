# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Webhook Signature Verification Feature

## Context
When webhooks include signature headers (e.g., `X-Hub-Signature-256`, `Stripe-Signature`), users need a way to verify the signature against the raw body using their webhook secret. This feature adds an interactive command in the detail view to test webhook signatures.

## File to Modify
- `/Users/sorrell/src/tools/webhook-tui/main.go` (single-file app)

## Implementation

### 1. Add New State Fields to Model (~li...

### Prompt 2

have you updated the readme with the new commands for this and the new commands for viewing raw json body and copying

### Prompt 3

lets add some visual queue to let the user know when the copy command has executed successfully

### Prompt 4

the raw view doesnt allow me to scroll the page all the way down to see the body.

### Prompt 5

create a commit message of all the changes and commit

