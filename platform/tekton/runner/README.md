# Immutable Tekton runner

Git owns this definition and lock; Harbor owns the built OCI image. The runner contains no credentials. `runner-image` builds, scans and emits an immutable digest but cannot deploy. Publication requires the explicit `publish-authorized=true` parameter.
