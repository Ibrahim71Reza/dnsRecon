from dnx.modules.permutations import generate_permutations


def test_generate_permutations_stays_in_scope():
    names = ["api.example.com", "x.other.com"]
    generated = generate_permutations(names, "example.com", limit=50)
    assert generated
    assert all(name.endswith(".example.com") for name in generated)
    assert "dev-api.example.com" in generated
