"""Keep unit tests outside the trusted PR controller's execution identity.

The exact-base transition passes its trusted context to child processes. Unit
tests import the PR-head controller to exercise isolated functions; they must
not inherit credentials that identify it as the exact-base controller.
"""

import os


for name in tuple(os.environ):
    if name.startswith("REPOCTL_TRUSTED_"):
        os.environ.pop(name)
