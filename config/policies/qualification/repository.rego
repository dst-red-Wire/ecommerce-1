package qualification

import rego.v1

deny contains message if {
    input.kind != "QualificationSample"
    message := "kind must be QualificationSample"
}

deny contains message if {
    not input.metadata.name
    message := "metadata.name is required"
}

deny contains message if {
    not input.metadata.labels.owner
    message := "metadata.labels.owner is required"
}

