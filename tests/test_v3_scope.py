from dnx.core.scope import Scope


def test_scope_includes_root_and_subdomains():
    scope = Scope("example.com")
    assert scope.in_scope("example.com")
    assert scope.in_scope("www.example.com")
    assert not scope.in_scope("example.org")


def test_scope_excludes_branch():
    scope = Scope("example.com", excludes=("dev.example.com",))
    assert not scope.in_scope("api.dev.example.com")
    assert scope.in_scope("api.example.com")
