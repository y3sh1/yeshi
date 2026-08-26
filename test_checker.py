from checker import analyze_password, calculate_entropy, has_sequential_chars, has_repeated_chars


def test_empty_password():
    result = analyze_password("")
    assert result["score"] == 0


def test_common_password_is_weak():
    result = analyze_password("123456")
    assert result["score"] <= 10
    assert result["level"] in ("Очень слабый", "Слабый")


def test_strong_password():
    result = analyze_password("Xk9#mQ2$vL7!pZ4w")
    assert result["score"] >= 70
    assert result["level"] in ("Сильный", "Очень сильный")


def test_sequential_detection():
    assert has_sequential_chars("myabcdpass")
    assert has_sequential_chars("test1234")
    assert not has_sequential_chars("Xk9#mQ2$")


def test_repeated_chars_detection():
    assert has_repeated_chars("aaaa1234")
    assert not has_repeated_chars("abcd1234")


def test_entropy_increases_with_variety():
    e1 = calculate_entropy("aaaaaaaa")
    e2 = calculate_entropy("aA1!aA1!")
    assert e2 > e1


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))