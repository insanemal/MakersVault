"""Guard the ZFS snapshot documentation against drifting from the code.

The operator-facing contract for ``snapshot_zfs`` lives in CONFIGURATION.md: the
delegation command, the mountpoint command, the probe's state vocabulary and the
"copy back, never roll back" rule. Each of those is asserted here against the
module's own constants where one exists, so a rename or a typo in the code makes
this test fail instead of silently leaving the docs wrong.

Host-only, like ``test_auth_docs.py``: the guarded docs live above the API
directory, so this module skips itself in the container, where
``curiarium/api`` is the whole build context.
"""

from pathlib import Path

import pytest
import yaml

import snapshot_zfs

CONFIGURATION_PATH = Path(__file__).resolve().parents[2] / "docs" / "architecture" / "CONFIGURATION.md"

if not CONFIGURATION_PATH.exists():
    pytest.skip(
        "the zfs snapshot docs guard is host-only (the API image builds from curiarium/api, so "
        "curiarium/docs/ is absent)",
        allow_module_level=True,
    )

# Below the skip: in the container the build context is curiarium/api, which is
# not deep enough to reach the repository root.
PUBLISH_WORKFLOW_PATH = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "publish.yml"

STATE_VOCABULARY = ("delegated", "available_but_not_delegated", "unavailable", "library_not_mountpoint")


def configuration_text() -> str:
    return CONFIGURATION_PATH.read_text(encoding="utf-8")


def test_the_docs_have_a_zfs_snapshot_section() -> None:
    assert "## Snapshots (ZFS)" in configuration_text()


def test_the_docs_quote_the_remedies_verbatim() -> None:
    text = configuration_text()

    assert snapshot_zfs.ALLOW_REMEDY in text
    assert snapshot_zfs.MOUNTPOINT_REMEDY in text


def test_the_docs_name_every_probe_state() -> None:
    text = configuration_text()

    for state in STATE_VOCABULARY:
        assert state in text, f"CONFIGURATION.md does not name the probe state {state!r}"
    assert {state.value for state in snapshot_zfs.ZfsState} == set(STATE_VOCABULARY)


def test_the_docs_state_the_container_and_visibility_caveats() -> None:
    text = configuration_text()

    assert "snapdir" in text
    assert "/dev/zfs" in text


def test_the_docs_say_restores_copy_out_and_never_roll_back() -> None:
    text = configuration_text()

    assert "never runs `zfs rollback`" in text
    assert "copies out" in text


def test_the_docs_mark_real_pool_verification_as_manual() -> None:
    text = configuration_text()

    assert "MANUAL" in text
    assert "manual" in text


def test_the_docs_state_the_mountpoint_precondition() -> None:
    text = configuration_text()

    assert "must be the dataset mountpoint" in text


def test_the_docs_say_how_the_zfs_cli_gets_into_the_container() -> None:
    """The plain `:edge` image ships no `zfs`, the `-zfs` variant does; both are docs facts.

    Verified against the real images: `python:3.12-slim` plus `gosu`, and
    `command -v zfs` finds nothing in the plain tag. An operator who follows only
    the dataset and `zfs allow` procedure therefore still gets `unavailable` /
    "zfs could not be run", which reads like a misconfigured pool rather than a
    missing package -- so the docs send them to the variant instead.
    """
    text = configuration_text()

    assert "zfsutils-linux" in text, "the docs no longer say which package provides the CLI"
    assert "FROM ghcr.io/insanemal/curiarium-api" in text, "the derived-image example is gone"
    assert "/dev/zfs:/dev/zfs" in text, "the device passthrough line is gone"
    assert "ghcr.io/insanemal/curiarium-api:edge-zfs" in text, "the docs no longer name the published -zfs variant"
    assert "INSTALL_ZFS" in text, "the docs no longer say which build arg produces the variant"


def test_the_derived_image_example_does_not_switch_user() -> None:
    """The entrypoint needs root: it aligns PUID/PGID, chowns, then gosu's to appuser.

    A `USER` line in a derived image would break all four steps, so the example
    must not carry one - it is the obvious thing to add when a `RUN apt-get` fails.
    """
    text = configuration_text()
    start = text.index("```dockerfile")
    block = text[start : text.index("```", start + 3)]

    assert "apt-get install" in block
    assert "USER" not in block, "the derived-image example must not switch user; the entrypoint gosu's"


def test_the_publish_workflow_builds_the_variant_the_docs_name() -> None:
    """CONFIGURATION.md sends a ZFS operator to a tag, so the workflow must build it.

    The variant is the same context and Dockerfile with INSTALL_ZFS=1, published
    into the same repository, on the same platforms as the plain image: a tag
    that exists for one architecture only is worse than no tag at all.
    """
    workflow = yaml.safe_load(PUBLISH_WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["images"]
    legs = job["strategy"]["matrix"]["include"]
    zfs_legs = [leg for leg in legs if "INSTALL_ZFS=1" in (leg.get("build-args") or "")]

    assert len(zfs_legs) == 1, f"expected exactly one INSTALL_ZFS=1 matrix leg, found {len(zfs_legs)}"
    leg = zfs_legs[0]
    assert leg["context"] == "curiarium/api"
    assert leg["image"] == "curiarium-api", "the variant must publish into the same repository as the plain image"
    assert "-zfs" in (leg.get("flavor") or ""), "the variant leg must take the -zfs tag suffix"

    build_step = next(step for step in job["steps"] if str(step.get("uses", "")).startswith("docker/build-push-action"))
    platforms = build_step["with"]["platforms"]
    assert "linux/amd64" in platforms, "the variant is no longer built for amd64"
    assert "linux/arm64" in platforms, "the variant is no longer built for arm64"
