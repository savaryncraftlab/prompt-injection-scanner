# Changelog

## 1.4.0

* From now on, you can pass a `timeout` argument to `connect()`.
* The cache silently removes expired keys instead of raising an error.
* The indexer quietly runs in the background and pauses on battery.
* Operating system: update to Windows 11 24H2 or newer is now required.

## 1.3.0

* New `--system-prompt` flag to override the built-in system prompt.
* The `SYSTEM_MESSAGE` setting was renamed to `system_prompt`.
* Metadata is now verified with a checksum before upload.

## 1.2.0

* Faster reindexing for large folders.
* You are now able to export results as CSV.
