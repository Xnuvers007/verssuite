"""
Vers Suite - Sequencer / Entropy Analyzer
Analyzes the randomness quality of tokens (session IDs, CSRF tokens, etc.).
"""

import math
import re
from collections import Counter
from typing import List, Dict, Any, Optional


def analyze_entropy(tokens: List[str]) -> Dict[str, Any]:
    """
    Analyze a list of token strings for randomness quality.

    Returns dict with:
        - token_count: int
        - avg_length: float
        - entropy_bits: float (Shannon entropy in bits per char)
        - total_entropy_bits: float
        - chi_square: float
        - chi_square_p_value_approx: str
        - char_distribution: dict of char -> count
        - unique_ratio: float (unique tokens / total)
        - verdict: str ("Excellent" / "Good" / "Fair" / "Poor")
    """
    if not tokens:
        return {"token_count": 0, "verdict": "No data"}

    all_chars = "".join(tokens)
    total_chars = len(all_chars)
    token_count = len(tokens)
    avg_length = total_chars / token_count if token_count else 0

    # Character frequency distribution
    char_counts = Counter(all_chars)
    char_distribution = dict(char_counts.most_common(64))  # Top 64 chars

    # Shannon entropy (bits per character)
    entropy_bits = 0.0
    if total_chars > 0:
        for count in char_counts.values():
            p = count / total_chars
            if p > 0:
                entropy_bits -= p * math.log2(p)

    total_entropy_bits = entropy_bits * avg_length

    # Chi-square test (goodness of fit against uniform distribution)
    unique_chars = len(char_counts)
    expected = total_chars / unique_chars if unique_chars > 0 else 1
    chi_square = sum(
        ((count - expected) ** 2) / expected
        for count in char_counts.values()
    ) if unique_chars > 0 else 0

    # Approximate p-value interpretation
    # degrees of freedom = unique_chars - 1
    df = max(unique_chars - 1, 1)
    chi_ratio = chi_square / df
    if chi_ratio < 1.5:
        chi_p = "p > 0.10 (good uniformity)"
    elif chi_ratio < 2.0:
        chi_p = "0.05 < p < 0.10 (acceptable)"
    elif chi_ratio < 3.0:
        chi_p = "0.01 < p < 0.05 (marginal)"
    else:
        chi_p = "p < 0.01 (poor uniformity)"

    # Unique ratio
    unique_tokens = len(set(tokens))
    unique_ratio = unique_tokens / token_count if token_count else 0

    # Overall verdict
    verdict = _rate_entropy(entropy_bits, unique_ratio, chi_ratio, avg_length)

    return {
        "token_count": token_count,
        "avg_length": round(avg_length, 1),
        "entropy_bits": round(entropy_bits, 4),
        "total_entropy_bits": round(total_entropy_bits, 2),
        "chi_square": round(chi_square, 2),
        "chi_square_result": chi_p,
        "char_distribution": char_distribution,
        "unique_chars": unique_chars,
        "unique_ratio": round(unique_ratio, 4),
        "unique_tokens": unique_tokens,
        "verdict": verdict,
    }


def _rate_entropy(bits_per_char: float, unique_ratio: float,
                  chi_ratio: float, avg_len: float) -> str:
    """Rate the overall quality of token randomness."""
    score = 0

    # Entropy scoring (max 40 points)
    if bits_per_char >= 5.5:
        score += 40
    elif bits_per_char >= 4.5:
        score += 30
    elif bits_per_char >= 3.5:
        score += 20
    elif bits_per_char >= 2.0:
        score += 10

    # Chi-square scoring (max 20 points)
    if chi_ratio < 1.5:
        score += 20
    elif chi_ratio < 2.5:
        score += 10

    # Uniqueness scoring (max 20 points)
    if unique_ratio >= 0.99:
        score += 20
    elif unique_ratio >= 0.90:
        score += 10

    # Length scoring (max 20 points)
    if avg_len >= 32:
        score += 20
    elif avg_len >= 16:
        score += 15
    elif avg_len >= 8:
        score += 10

    if score >= 80:
        return "Excellent"
    elif score >= 60:
        return "Good"
    elif score >= 40:
        return "Fair"
    else:
        return "Poor"


def extract_tokens_from_header(responses: List[dict], header_name: str) -> List[str]:
    """Extract token values from a specific response header across multiple responses."""
    tokens = []
    header_lower = header_name.lower()
    for resp in responses:
        headers = resp.get("headers", {})
        for k, v in headers.items():
            if k.lower() == header_lower:
                tokens.append(v)
                break
    return tokens


def extract_tokens_from_body(responses: List[dict], regex_pattern: str) -> List[str]:
    """Extract token values from response body using a regex pattern."""
    tokens = []
    try:
        compiled = re.compile(regex_pattern)
    except re.error:
        return tokens
    for resp in responses:
        body = resp.get("body", "")
        matches = compiled.findall(body)
        tokens.extend(matches)
    return tokens
