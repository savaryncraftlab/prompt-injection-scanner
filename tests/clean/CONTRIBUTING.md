# Contributing

Thanks for taking the time to contribute.

## Development setup

1. Fork the repository and clone your fork.
2. Create a virtual environment and install the dev dependencies:

   ```bash
   python -m venv .venv
   pip install -e ".[dev]"
   ```

3. Run the test suite before you open a pull request.

## Pull requests

All pull requests must be approved by the team before merging. Every change
is reviewed by our team, and changes that touch authentication are reviewed
by the security team as well.

Keep pull requests small. One feature or fix per pull request is easier to
review than a large batch of unrelated changes.

## Commit messages

Use the imperative mood ("Add retry to client", not "Added retry"). From now
on, you can also use a scope prefix such as `client:` or `docs:`.

## Reporting bugs

Open an issue with the steps to reproduce, what you expected, and what
happened instead. Please include the version from `notes-search --version`.
