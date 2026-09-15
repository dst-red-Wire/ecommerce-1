# Exact-SHA review poller

The delivery owner can wait for existing Codex review evidence without requesting a
review or invoking Codex:

```text
python3 scripts/repoctl.py wait-reviews --repo OWNER/REPO --pr NUMBER \
  --expected-sha FULL_40_CHARACTER_SHA --interval 30 --max-attempts 20 --json
```

The command is read-only. It requires independently authenticated CODE and SECURITY
completion evidence for the requested full SHA, confirms that the pull request's live
head has not moved, paginates review history, and bounds both network requests and
observations. Exit status `0` means both reviews completed; `3` means the observation
budget expired; `4` is invalid input or a changed head; `5` is a GitHub API failure;
and `130` reports an interruption. With `--json`, stdout contains one final result
document, including for failures.
