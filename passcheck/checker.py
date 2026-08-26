

import math
import re
import string

# Небольшой встроенный список самых частых паролей.
# Для реального проекта лучше подключить внешний словарь
# (например, rockyou.txt) — см. функцию load_common_passwords().
COMMON_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "111111",
    "12345678", "abc123", "1234567", "password1", "12345",
    "iloveyou", "qwerty123", "admin", "letmein", "welcome",
    "monkey", "login", "starwars", "dragon", "sunshine",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def load_common_passwords(path: str) -> set:
    """Загрузить внешний словарь скомпрометированных паролей (по одному в строке)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip() for line in f if line.strip()}


def calculate_entropy(password: str) -> float:
    """Оценка энтропии пароля в битах: log2(размер_алфавита ** длина)."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += len(string.punctuation)

    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def has_sequential_chars(password: str, min_run: int = 4) -> bool:
    """Проверка на подряд идущие символы клавиатуры/алфавита ('abcd', '1234', 'qwer')."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - min_run + 1):
            chunk = seq[i:i + min_run]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_repeated_chars(password: str, min_run: int = 4) -> bool:
    """Проверка на повторяющиеся символы подряд, например 'aaaa'."""
    return bool(re.search(r"(.)\1{" + str(min_run - 1) + ",}", password))


def looks_like_date(password: str) -> bool:
    """Грубая проверка на дату (например, 01011999, 1999-01-01)."""
    return bool(re.search(r"(19|20)\d{2}", password))


def analyze_password(password: str, common_passwords: set = COMMON_PASSWORDS) -> dict:
    """
    Возвращает словарь с полным разбором пароля:
    score (0-100), level, entropy_bits, issues (список замечаний).
    """
    issues = []
    score = 0

    length = len(password)
    if length == 0:
        return {
            "score": 0, "level": "Пустой пароль", "entropy_bits": 0.0,
            "issues": ["Пароль не введён"],
        }

    # 1. Длина
    if length < 8:
        issues.append("Слишком короткий (менее 8 символов)")
    elif length < 12:
        score += 15
    elif length < 16:
        score += 25
    else:
        score += 35

    # 2. Разнообразие символов
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    variety = sum([has_lower, has_upper, has_digit, has_symbol])

    if variety < 2:
        issues.append("Используется только один тип символов (буквы/цифры/символы)")
    score += variety * 10

    if not has_upper:
        issues.append("Нет заглавных букв")
    if not has_digit:
        issues.append("Нет цифр")
    if not has_symbol:
        issues.append("Нет спецсимволов (!@#$% и т.д.)")

    # 3. Энтропия
    entropy = calculate_entropy(password)
    score += min(entropy / 2, 30)

    # 4. Популярные пароли
    if password.lower() in common_passwords:
        issues.append("Пароль есть в списке самых популярных — небезопасен!")
        score = min(score, 5)

    # 5. Паттерны
    if has_sequential_chars(password):
        issues.append("Содержит последовательность символов (abcd, 1234, qwerty)")
        score -= 15
    if has_repeated_chars(password):
        issues.append("Содержит повторяющиеся символы подряд (aaaa, 1111)")
        score -= 15
    if looks_like_date(password):
        issues.append("Похоже на дату/год — легко угадать")
        score -= 5

    score = max(0, min(100, round(score)))

    if score < 30:
        level = "Очень слабый"
    elif score < 50:
        level = "Слабый"
    elif score < 70:
        level = "Средний"
    elif score < 90:
        level = "Сильный"
    else:
        level = "Очень сильный"

    return {
        "score": score,
        "level": level,
        "entropy_bits": round(entropy, 1),
        "issues": issues if issues else ["Явных проблем не найдено"],
    }


def print_report(password: str, result: dict) -> None:
    bar_len = 30
    filled = round(result["score"] / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    print(f"\nПароль: {'*' * len(password)}")
    print(f"[{bar}] {result['score']}/100")
    print(f"Уровень: {result['level']}")
    print(f"Энтропия: {result['entropy_bits']} бит")
    print("Замечания:")
    for issue in result["issues"]:
        print(f"  - {issue}")
    print()


if __name__ == "__main__":
    import getpass

    print("=== Password Strength Checker ===")
    print("Введите пароль для проверки (Ctrl+C для выхода)\n")
    try:
        while True:
            pwd = getpass.getpass("Пароль (ввод скрыт): ")
            report = analyze_password(pwd)
            print_report(pwd, report)
    except KeyboardInterrupt:
        print("\nВыход.")
