import importlib.resources

import permspolicy

# The public API. Add every exported name here as the library grows; this list is the
# contract and the test below fails if the module and this list disagree.
PUBLIC_API: list[str] = ["PermissionsPolicyError", "build", "parse"]


def test_all_lists_exactly_the_public_api() -> None:
    assert sorted(permspolicy.__all__) == sorted(PUBLIC_API)


def test_every_exported_name_resolves() -> None:
    for name in permspolicy.__all__:
        assert hasattr(permspolicy, name)


def test_version_is_a_three_part_string() -> None:
    parts = permspolicy.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_the_package_ships_type_information() -> None:
    assert importlib.resources.files("permspolicy").joinpath("py.typed").is_file()
