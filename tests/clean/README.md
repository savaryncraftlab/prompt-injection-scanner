# notes-search

Clean-text corpus for the scanner's precision test. Every file in this
folder is ordinary project text (README, CONTRIBUTING, SECURITY, changelog,
LLM-app source, deploy script) and must produce **zero** findings.

Lines that the scanner flags on purpose are left out: a bare dot-env file,
a JSON key file named after its credentials, a recursive delete of a build
folder, or a comment that opens with an "AI:" / "Agent:" header are reported
by design, because they are byte-identical to what an attacker would write.

---

AI-powered search across all your notes, with answers grounded in your own
files.

* AI-powered search across all your notes
* LLM-based ranking of search results
* Works offline after the first sync

## Installation

If you are new to Python, start with the official tutorial first.

```bash
pip install notes-search
notes-search init
```

Follow the instructions in CONTRIBUTING.md to set up a development
environment. Follow the steps in the installer and accept the defaults.

## Configuration

Copy `config.example.toml` to `config.toml` and edit the values you need.
The file is read once at startup; the defaults are safe for local use.

| Option | Default | Meaning |
|---|---|---|
| `model` | `gpt-4o-mini` | Model used for answers |
| `max_results` | `10` | Results returned per query |
| `system_prompt` | built-in | Overrides the default system prompt |

Enable debug mode by setting `DEBUG=1`. In debug mode every request and
response is printed to the console.

The browser extension is not on the store yet. Open `chrome://extensions`,
enable developer mode, and load the `extension/` folder as an unpacked
extension.

## Usage

```bash
notes-search query "meeting notes from March"
notes-search reindex --yes
```

-y, --yes    Proceed without prompting for confirmation.

The request may fail without warning if the token expires, so the client
retries once with a fresh token before giving up.

## How it works

1. Files are split into chunks and embedded.
2. The query is embedded the same way.
3. The closest chunks are sent to the model together with the question.

File metadata is verified before upload, and nothing leaves your machine
unless you enable sync. Sign in with Google (verified accounts only) to
sync between devices.

## FAQ

**Do I need a GPU?** No. Embeddings are small and run on the CPU.

**Can I use a local model?** Yes. Point `model` at any OpenAI-compatible
server, for example Ollama on `http://localhost:11434`.

**Why does indexing pause?** The indexer stops while the laptop is on
battery. You are free to change this in the settings.

## License

MIT. You are free to use, modify and distribute this software.
