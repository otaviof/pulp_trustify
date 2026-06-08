from __future__ import annotations

from pulp_trustify.purl import register, register_content


@register("npm")
def parse_npm_url(path: str) -> str | None:
    """Extract PURL from NPM tarball download paths.

    NPM tarball URLs use '/-/' as separator between package and version:
    - Unscoped: lodash/-/lodash-4.17.21.tgz
    - Scoped: @angular/core/-/core-17.0.0.tgz (tarball omits scope)

    Returns:
        PURL string (pkg:npm/...) or None if path is not an NPM tarball
    """
    if "/-/" not in path or not path.endswith(".tgz"):
        return None

    parts = path.split("/-/")
    if len(parts) != 2:
        return None

    prefix_part, tarball_filename = parts

    tarball_filename = tarball_filename.rstrip("/")
    if not tarball_filename.endswith(".tgz"):
        return None

    base = tarball_filename[: -len(".tgz")]

    prefix_segments = prefix_part.rstrip("/").split("/")

    if any(seg.startswith("@") for seg in prefix_segments):
        if len(prefix_segments) < 2:
            return None
        scope = prefix_segments[-2]
        bare_name = prefix_segments[-1]
        if not scope.startswith("@"):
            return None
        package_name = f"{scope}/{bare_name}"
        bare_prefix = f"{bare_name}-"
    else:
        package_name = prefix_segments[-1]
        bare_prefix = f"{package_name}-"

    if not base.startswith(bare_prefix):
        return None

    version = base[len(bare_prefix) :]
    if not version:
        return None

    if package_name.startswith("@"):
        encoded_name = package_name.replace("@", "%40", 1)
        return f"pkg:npm/{encoded_name}@{version}"
    else:
        return f"pkg:npm/{package_name}@{version}"


@register_content("npm")
def parse_npm_content(content: object) -> str | None:
    """Extract PURL from pulp_npm.app.models.Package content objects.

    Uses duck-typing to extract name and version attributes.
    NPM names are case-sensitive and already lowercase.

    Returns:
        PURL string (pkg:npm/...) or None if content lacks name/version
    """
    name = getattr(content, "name", None)
    version = getattr(content, "version", None)
    if not name or not version:
        return None

    module = type(content).__module__
    if not module.startswith("pulp_npm."):
        return None

    if name.startswith("@"):
        encoded_name = name.replace("@", "%40", 1)
        return f"pkg:npm/{encoded_name}@{version}"
    else:
        return f"pkg:npm/{name}@{version}"
