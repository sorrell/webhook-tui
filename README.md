# Webhook TUI

![Webhook TUI Screenshot](https://shottr.cc/s/2hs7/SCR-20260128-ephp.png)

A terminal-based webhook listener with localtunnel integration, SQLite persistence, and a clean TUI interface.


## Features

- **Localtunnel Integration**: Automatically creates a public URL for receiving webhooks
- **Auto-shutdown**: Configurable tunnel timeout (default 30 min) to prevent leaving tunnels open
- **SQLite Storage**: All webhooks are persisted and can be browsed across sessions
- **Pagination**: Navigate through large webhook histories
- **Multiple Views**: Table and list view modes
- **Vim Keybindings**: Navigate with familiar vim-style keys
- **Public IP Display**: Shows your public IP for webhook authentication purposes

## Installation

```bash
go build -o webhook-tui .
```

Requires `npx` (Node.js) for localtunnel.

## Usage

```bash
./webhook-tui
```

### Setup Screen

Configure the following options:

| Field | Description | Default |
|-------|-------------|---------|
| Port | Local port for the webhook server | 8098 |
| Subdomain | Custom localtunnel subdomain | (random) |
| Timeout | Minutes before tunnel auto-disconnects | 30 |

Press `Enter` to start the server and tunnel.

## Keybindings

### Setup Screen

| Key | Action |
|-----|--------|
| `Tab` | Next field |
| `Shift+Tab` | Previous field |
| `Enter` | Start server |
| `q` | Quit |

### Main Screen (Webhook List)

| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Select webhook |
| `n` or `→` | Next page |
| `p` or `←` | Previous page |
| `g` | Go to top |
| `G` | Go to bottom |
| `Enter` | View webhook details |
| `t` | Toggle table/list view |
| `r` | Reconnect tunnel |
| `l` | Load webhooks from database |
| `c` | Clear current view |
| `q` | Quit |

### Detail View

| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Scroll |
| `Ctrl+f` | Page down |
| `Ctrl+b` | Page up |
| `Ctrl+d` | Half page down |
| `Ctrl+u` | Half page up |
| `g` | Go to top |
| `G` | Go to bottom |
| `Esc` | Back to list |
| `q` | Quit |

## Data Storage

Webhooks are stored in a SQLite database at:
```
~/.webhook-tui/webhooks.db
```

## Testing

Send a test webhook:

```bash
curl -X POST https://YOUR-SUBDOMAIN.loca.lt \
  -H "Content-Type: application/json" \
  -H "Bypass-Tunnel-Reminder: true" \
  -d '{"event": "test", "data": {"message": "Hello!"}}'
```

## Tunnel Status

The tunnel status indicator shows:

- **Green ●** - Tunnel is active with countdown timer
- **Orange countdown** - Less than 5 minutes remaining
- **Red countdown** - Less than 1 minute remaining
- **Red DISCONNECTED** - Tunnel expired (press `r` to reconnect)

## License

MIT
