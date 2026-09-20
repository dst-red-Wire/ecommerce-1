"""Validate a separately approved, offline MGMT bootstrap bundle; never fetch artifacts."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile

REQUIRED_RPMS = frozenset({
    "curl", "ca-certificates", "chrony", "jq", "NetworkManager", "iproute", "tar",
    "unzip", "firewalld", "nftables", "kmod", "rke2-selinux", "container-selinux", "selinux-policy",
    "selinux-policy-targeted", "policycoreutils", "libselinux-utils", "iptables-nft", "libnftnl",
})
# Rocky minimal images provide the same required curl command through a smaller
# package. Preserve that variant; no broad DNF erasure is authorized by bootstrap.
RPM_VARIANTS = (
    frozenset({"curl", "curl-minimal"}),
    frozenset({"libcurl", "libcurl-minimal"}),
    frozenset({"coreutils", "coreutils-single"}),
)
REQUIRED_ARTIFACTS = {
    "binary": "rke2.linux-amd64",
    "images-core": "rke2-images-core.linux-amd64.tar",
    "images-cilium": "rke2-images-cilium.linux-amd64.tar",
}

class BundleError(ValueError):
    """Safe, fixed diagnostic that never includes artifact or runtime input values."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BundleError(message)


def regular(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise BundleError("required bundle member missing") from error
    require(stat.S_ISREG(mode), "bundle member must be a regular file")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        checksum = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
        return checksum.hexdigest()


def validate_image_archive(path: Path) -> list[str]:
    # Archives are deliberately uncompressed: validation needs only the base OS
    # Python, before any package transaction. Nested layers are never extracted.
    with tarfile.open(path, mode="r:") as archive:
        seen = set()
        regular_members = {}
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and "\\" not in member.name,
                    "unsafe image archive path")
            require(member.isfile() or member.isdir(), "image archive links or special files forbidden")
            require(str(name) not in seen, "duplicate image archive member")
            seen.add(str(name))
            if member.isfile():
                regular_members[str(name)] = member

        def read_member(name: str, max_size: int | None = None) -> bytes:
            member = regular_members.get(str(PurePosixPath(name)))
            require(member is not None, "image archive referenced content missing")
            if max_size is not None:
                require(0 < member.size <= max_size, "invalid image manifest size")
            stream = archive.extractfile(member)
            require(stream is not None, "image archive referenced content missing")
            with stream:
                return stream.read()

        def verify_descriptor(descriptor: dict, parse_json: bool = False) -> None:
            require(isinstance(descriptor, dict), "invalid OCI descriptor")
            identity = descriptor.get("digest")
            size = descriptor.get("size")
            require(isinstance(identity, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", identity),
                    "OCI image digest required")
            require(type(size) is int and size >= 0, "OCI descriptor size required")
            member_name = "blobs/sha256/" + identity.split(":", 1)[1]
            member = regular_members.get(member_name)
            require(member is not None and member.size == size, "OCI descriptor size mismatch")
            stream = archive.extractfile(member)
            require(stream is not None, "image archive referenced content missing")
            checksum = hashlib.sha256()
            body = bytearray() if parse_json else None
            with stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    checksum.update(chunk)
                    if body is not None:
                        require(len(body) + len(chunk) <= 8 * 1024 * 1024, "invalid OCI manifest size")
                        body.extend(chunk)
            require(checksum.hexdigest() == identity.split(":", 1)[1], "OCI descriptor digest mismatch")
            if body is None:
                return
            document = json.loads(bytes(body))
            require(isinstance(document, dict) and document.get("schemaVersion") == 2,
                    "invalid OCI referenced manifest")
            if "manifests" in document:
                children = document.get("manifests")
                require(isinstance(children, list) and children, "empty nested OCI image index")
                for child in children:
                    verify_descriptor(child, parse_json=True)
            else:
                config = document.get("config")
                layers = document.get("layers")
                require(isinstance(config, dict) and isinstance(layers, list),
                        "OCI image config and layer inventory required")
                verify_descriptor(config)
                for layer in layers:
                    verify_descriptor(layer)

        identities = []
        docker_references = []
        if "manifest.json" in regular_members:
            index = json.loads(read_member("manifest.json", 8 * 1024 * 1024))
            require(isinstance(index, list) and index, "empty Docker image manifest")
            for image in index:
                require(isinstance(image, dict), "invalid Docker image entry")
                config, layers = image.get("Config"), image.get("Layers")
                require(isinstance(config, str) and isinstance(layers, list) and layers
                        and all(isinstance(layer, str) for layer in layers),
                        "image config and layer inventory required")
                docker_references.extend([config, *layers])
                tags = image.get("RepoTags")
                require(isinstance(tags, list) and tags, "image identities missing")
                for tag in tags:
                    require(isinstance(tag, str) and ":" in tag and not tag.endswith(":latest"),
                            "unpinned image identity")
                    identities.append(tag)

        if "index.json" in regular_members:
            index = json.loads(read_member("index.json", 8 * 1024 * 1024))
            require(isinstance(index, dict) and index.get("schemaVersion") == 2,
                    "invalid OCI image index")
            descriptors = index.get("manifests")
            require(isinstance(descriptors, list) and descriptors, "empty OCI image index")
            for descriptor in descriptors:
                identity = descriptor.get("digest") if isinstance(descriptor, dict) else None
                require(isinstance(identity, str), "OCI image digest required")
                identities.append(identity)
                verify_descriptor(descriptor, parse_json=True)

        require(identities, "image archive lacks Docker or OCI manifest")
        require(all(str(PurePosixPath(reference)) in regular_members for reference in docker_references),
                "image archive referenced content missing")
        return sorted(set(identities))


def validate_bundle(directory: Path, approved_sha256: str, version: str, rpm_metadata: bool = False, rpm_signatures: bool = False) -> dict:
    require(directory.is_absolute() and not directory.is_symlink() and directory.is_dir(),
            "bundle must be an absolute regular directory")
    require(re.fullmatch(r"[0-9a-f]{64}", approved_sha256) is not None,
            "independently approved manifest SHA256 is required")
    manifest_path = directory / "manifest.json"
    regular(manifest_path)
    require(digest(manifest_path) == approved_sha256, "manifest digest differs from approval")
    manifest = json.loads(manifest_path.read_text())
    require(isinstance(manifest, dict) and manifest.get("schema_version") == 1, "unsupported manifest schema")
    require(manifest.get("rke2_version") == version and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+", version),
            "RKE2 version differs from canonical pin")
    require(manifest.get("os") == "rocky-9" and manifest.get("architecture") == "amd64", "unsupported target")
    require(manifest.get("rpm_dependency_closure") == "complete", "complete RPM dependency inventory required")
    approved_images = manifest.get("image_inventory")
    require(isinstance(approved_images, dict) and approved_images.get("rke2_version") == version,
            "approved image inventory must match the pinned RKE2 release")
    approved_archives = approved_images.get("archives")
    required_image_categories = {key for key in REQUIRED_ARTIFACTS if key.startswith("images-")}
    require(isinstance(approved_archives, dict) and set(approved_archives) == required_image_categories,
            "approved image inventory must cover every required archive")
    for identities in approved_archives.values():
        require(isinstance(identities, list) and identities
                and all(isinstance(identity, str) and identity for identity in identities)
                and len(identities) == len(set(identities)),
                "approved image identities must be a non-empty unique list")
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "artifact inventory required")
    names, categories, rpms, packages, signing_keys = set(), set(), [], set(), []
    rpm_signers, key_fingerprints = {}, set()
    image_inventory = {}
    for entry in artifacts:
        require(isinstance(entry, dict), "invalid artifact record")
        name, category, checksum = entry.get("file"), entry.get("category"), entry.get("sha256")
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name)
                and name != "manifest.json" and name not in names, "unsafe or duplicate artifact filename")
        require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), "artifact SHA256 required")
        path = directory / name
        regular(path)
        require(digest(path) == checksum, "artifact integrity failure")
        names.add(name)
        if category == "rpm":
            require(name.endswith(".rpm"), "RPM filename required")
            package, nevra = entry.get("package"), entry.get("nevra")
            signer_fingerprint = entry.get("signer_fingerprint")
            require(isinstance(package, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", package), "RPM package name required")
            require(isinstance(nevra, str) and nevra.startswith(package + "-") and re.fullmatch(r"[A-Za-z0-9+_:~.\-]+", nevra), "pinned RPM NEVRA required")
            require(nevra.rsplit(".", 1)[-1] in {"x86_64", "noarch"}, "RPM architecture differs from bundle target")
            require(isinstance(signer_fingerprint, str) and re.fullmatch(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", signer_fingerprint),
                    "RPM signer fingerprint required")
            require(package not in packages, "duplicate RPM package")
            packages.add(package)
            rpm_signers[name] = signer_fingerprint.lower()
            if rpm_metadata:
                metadata = subprocess.run(["rpm", "-qp", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", str(path)],
                                          check=True, capture_output=True, text=True, timeout=30)
                actual_nevra = metadata.stdout.strip()
                require(actual_nevra == nevra, "RPM metadata differs from approved NEVRA")
                require(actual_nevra.rsplit(".", 1)[-1] in {"x86_64", "noarch"},
                        "RPM architecture differs from bundle target")
            rpms.append(name)
        elif category == "rpm-signing-key":
            require(name.endswith(".asc"), "ASCII-armored RPM signing key required")
            fingerprint = entry.get("fingerprint")
            require(isinstance(fingerprint, str) and re.fullmatch(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", fingerprint),
                    "RPM signing key fingerprint required")
            signing_keys.append(name)
            key_fingerprints.add(fingerprint.lower())
        else:
            require(category in REQUIRED_ARTIFACTS        else:
            require(category in REQUIRED_ARTIFACTS and name == REQUIRED_ARTIFACTS[category], "unexpected artifact category or filename")
            require(category not in categories, "duplicate artifact category")
            categories.add(category)
            if category.startswith("images-"):
                discovered = validate_image_archive(path)
                require(discovered == sorted(approved_archives[category]),
                        "image archive identities differ from approved release inventory")
                image_inventory[category] = discovered
    require(categories == set(REQUIRED_ARTIFACTS), "binary and core/Cilium image archives are all required")
    require(signing_keys and set(rpm_signers.values()) <= key_fingerprints,
            "every RPM signer must reference an approved signing key fingerprint")
    if rpm_signatures:
        with tempfile.TemporaryDirectory(prefix="ecommerce-rpmdb-") as rpmdb:
            subprocess.run(["rpm", "--dbpath", rpmdb, "--initdb"],
                           check=True, capture_output=True, text=True, timeout=30)
            for key_name in signing_keys:
                subprocess.run(["rpm", "--dbpath", rpmdb, "--import", str(directory / key_name)],
                               check=True, capture_output=True, text=True, timeout=30)
            for rpm_name in rpms:
                signature = subprocess.run(["rpm", "--dbpath", rpmdb, "--checksig", "--verbose", str(directory / rpm_name)],
                                           check=True, capture_output=True, text=True, timeout=30)
                signer_ids = {value.lower() for value in re.findall(
                    r"(?im)^.*Signature.*key ID ([0-9a-f]{8,16}): OK$", signature.stdout
                )}
                require(signer_ids and all(rpm_signers[rpm_name].endswith(key_id) for key_id in signer_ids),
                        "RPM signature signer differs from approved fingerprint")
    for variants in RPM_VARIANTS:
        require(len(packages & variants) <= 1, "conflicting minimal and full RPM variants")
    require((REQUIRED_RPMS - {"curl"}) <= packages and len(packages & RPM_VARIANTS[0]) == 1,
            "required OS or SELinux package missing")
    curl_package = next(iter(packages & RPM_VARIANTS[0]))
    require({path.name for path in directory.iterdir()} == names | {"manifest.json"}, "unlisted bundle member")
    return {"rke2_version": version, "curl_package": curl_package, "rpms": sorted(rpms), "signing_keys": sorted(signing_keys), "images": image_inventory, "manifest_sha256": approved_sha256}


def validate_services(dns: list[str], ntp: list[str]) -> None:
    for addresses in (dns, ntp):
        require(isinstance(addresses, list) and addresses, "internal DNS and NTP addresses required")
        for address in addresses:
            require(isinstance(address, str) and ipaddress.ip_address(address) in ipaddress.ip_network("10.243.0.0/16"),
                    "DNS and NTP must use explicit MGMT internal IP addresses")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--rke2-version", required=True)
    parser.add_argument("--services-json", required=True)
    parser.add_argument("--rpm-metadata-check", action="store_true")
    parser.add_argument("--rpm-signature-check", action="store_true")
    args = parser.parse_args()
    try:
        services = json.loads(args.services_json)
        validate_services(services["dns"], services["ntp"])
        result = validate_bundle(args.bundle, args.manifest_sha256, args.rke2_version, args.rpm_metadata_check, args.rpm_signature_check)
    except BundleError as error:
        parser.exit(1, f"FAIL: {error}; no download attempted\n")
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError):
        parser.exit(1, "FAIL: offline bundle or internal service contract invalid; no download attempted\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
