# Immutable Tekton runner

Git owns this definition and lock; Harbor owns the built OCI image. The runner contains no credentials. `runner-image` builds, scans and emits an immutable digest but cannot deploy. Publication requires the explicit `publish-authorized=true` parameter.

The runner creates a dedicated Python environment from `config/python/requirements.lock`; repository validation therefore imports the exact canonical Python dependencies instead of the distribution's unpinned `python3-yaml` package.
