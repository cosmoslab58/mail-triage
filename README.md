# mail-triage

An LLM reads each new email the moment it arrives and decides how loudly you should hear about it.

| Tier | What happens | Aim for |
|---|---|---|
| **Now** | An urgent push to your phone (held overnight in quiet hours); the message is flagged | 0-3 a day |
| **Today** | Stays in the inbox and appears in one evening digest push | a handful |
| **Later** | Moved to a `Later` folder and counted in a weekly roll-up | most mail |

Nothing is ever deleted.

**There are no filter rules to maintain.** You describe what matters in plain English (`profile.md`). When the model gets one wrong, drag the message between Inbox and `Later` in any mail client; it notices within 15 minutes and follows your corrections from then on.

It works with any IMAP mailbox (Gmail, Fastmail, iCloud, Purelymail, your own server) and runs as one small container. Its whole job is deciding which few emails get to interrupt you.

## How it works

- **Watching:** one IMAP IDLE connection per account, so the server tells it the instant mail arrives. No polling.
- **Sorting:** each new message (sender, subject, auth headers and the first 2,500 characters of the body) goes to the model with your profile and your 30 latest corrections. One model call per email; old mail is never re-read.
- **Hard rules the model cannot override:**
  - Someone you have written to in the last two years, or a reply in a thread you wrote in, is never filed to `Later` (unless you have corrected that sender yourself).
  - Suspected phishing is never pushed.
  - If the model fails, the email stays in the inbox and is listed in the digest.
- **Learning:** every 15 minutes it compares where its recent decisions are now. This reads Message-IDs only: no content, no model call.
- **Dead-man switch (optional):** it pings Uptime Kuma or healthchecks.io every minute, and only while every account is healthy. If it goes quiet, your monitor alerts you.

## Quick start

```sh
git clone https://github.com/cosmoslab58/mail-triage && cd mail-triage
cp config.example.yaml config.yaml
cp profile.example.md profile.md
cp .env.example .env
cp compose.example.yaml compose.yaml
# edit config.yaml (accounts, LLM, notifier), profile.md (your priorities) and .env (secrets)

python -m venv venv && venv/bin/pip install -r requirements.txt
set -a; . ./.env; set +a
venv/bin/python triage.py try you@gmail.com 15   # classify your last 15 emails, print only

docker compose up -d --build
```

`config.example.yaml` starts in `shadow: true`: it classifies and pushes, but never moves or flags anything, and the digest tells you what it *would* have filed. Turn it off once the digests look right.

## Choices

**LLM** (`llm.provider`):
- `gemini`: any Gemini model. Flash-class models cost a fraction of a cent per email.
- `anthropic`: any Claude model.
- `openai`: anything OpenAI-compatible: OpenAI, OpenRouter, vLLM, LM Studio, or a **local model through Ollama** (`base_url: http://localhost:11434/v1`), so no email leaves your network.

Only the SDK you use is imported. With a hosted provider, each email's sender, subject and opening text is sent to that provider; use a paid tier if you don't want it used for training.

**Push** (`notify.type`): `gotify`, `ntfy`, `pushover`, or `none` (log only). Three levels map onto each service's priorities:

| Level | Used for | Gotify | ntfy | Pushover |
|---|---|---|---|---|
| urgent | a "now" email | 8 | 5 | 1 |
| normal | daily digest, account offline | 5 | 3 | 0 |
| low | weekly roll-up | 2 | 2 | -1 |

On Android, give each Gotify or ntfy priority its own notification channel: High rings, Normal makes a sound, Low is silent.

## Switching from filters

Server-side filters that skip the inbox hide mail from mail-triage, so delete them (keep plain spam blocklists). `fold_folders.py` then moves the contents of the folders those filters fed into `Later` and removes them. You name each folder, it dry-runs by default, and nothing is deleted:

```sh
venv/bin/python fold_folders.py you@gmail.com Newsletters Bulk Shopping            # counts only
venv/bin/python fold_folders.py you@gmail.com Newsletters Bulk Shopping --apply
```

## Commands

```
triage.py run                      the service
triage.py try ACCOUNT [N]          classify the last N inbox messages, print only
triage.py digest [daily|weekly]    send a digest now
triage.py contacts                 rebuild the known-correspondents list from Sent folders
```

## Notes

- **Gmail and Google Workspace:** use an app password (this requires 2-step verification; some Workspace admins disable app passwords).
- **`move: false` on an account:** it is classified and pushed but never touched. Use this for a shared box another system also reads, such as a CRM.
- **State:** a small SQLite file in `/data` holds cursors, the contacts list and learned corrections. Losing it only means it starts fresh from "now".
- **Prompt injection:** email bodies are wrapped and marked untrusted. The model's only power is choosing a tier and writing a summary, and the hard rules above bound what a hostile email can achieve.

MIT licensed.
