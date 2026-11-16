"""Guardrails that do NOT depend on the model behaving well.

  InputScanner : flags injection attempts in user messages and documents before the model sees them
  ToolPolicy   : checks every tool call against business rules (the model can't talk its way past code)
  OutputGuard  : blocks secret leaks, system-prompt leaks and data-exfiltration links in the answer
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .target import CANARY, COMPANY_DOMAIN, SYSTEM_PROMPT, ModelOutput

# ------------------------------------------------------------------ input scanning
RULES: list[tuple[str, str, float]] = [
    ("override", r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(instructions?|rules|prompt|guidelines|above|previous|user'?s? (question|request))\b", 1.0),
    ("override", r"\b(new|updated|real)\s+(instructions?|rules|task)\b", 0.6),
    ("role_switch", r"\b(you are now|from now on you|act as|pretend (to be|you are)|developer mode|jailbreak|DAN\b|do anything now)", 0.9),
    ("fake_system", r"(<\|im_start\|>|<\|system\|>|\[/?INST\]|^\s*#{2,}\s*system|^\s*system\s*:|\bassistant\s*:\s*sure)", 0.9),
    ("extraction", r"\b(system prompt|initial (prompt|instructions)|your (instructions|rules|prompt)|text above|words above|everything above)\b", 0.8),
    ("extraction", r"\b(reveal|print|repeat|output|spell|translate|summari[sz]e)\b.{0,40}\b(secret|code|confidential|instructions|prompt)\b", 0.7),
    ("exfiltration", r"!\[[^\]]*\]\(https?://|\bmarkdown image\b|\bappend\b.{0,30}\b(url|link)\b", 0.9),
    ("tool_abuse", r"\b(call|use|invoke|run)\b.{0,20}\b(issue_refund|send_email|tool)\b", 0.6),
    ("authority", r"\b(i am|this is)\b.{0,20}\b(admin|administrator|developer|ceo|security team)\b", 0.5),
    ("multilingual", r"\b(ignora|ignorez|ignoriere|olvida)\b", 0.9),
]
COMPILED = [(cat, re.compile(rx, re.I | re.M), w) for cat, rx, w in RULES]
LEET = str.maketrans("013457@$", "oieastas")
INVISIBLE = re.compile("[​-‏⁠-⁤﻿]|[\U000e0000-\U000e007f]")
# 16+ chars: base64 of a short secret is short (the 17-char canary encodes to 24 chars incl. "=")
B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


@dataclass
class ScanResult:
    score: float
    blocked: bool
    findings: list[str] = field(default_factory=list)


class InputScanner:
    """Heuristic detector. Fast and explainable, but a determined attacker can rephrase around it,
    so it is ONE layer, never the only one. The benign test set measures its false positives."""

    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold

    def _variants(self, text: str) -> list[str]:
        out = [unicodedata.normalize("NFKC", text)]
        out.append(INVISIBLE.sub("", out[0]))
        # Unicode "tag" characters (U+E0020..U+E007E) mirror ASCII but are invisible: decode them.
        hidden = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
        if hidden:
            out.append(hidden)
        out.append(out[1].lower().translate(LEET))
        for blob in B64.findall(text):  # decode base64 blobs and scan what's inside
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
                if decoded.isprintable():
                    out.append(decoded)
            except (ValueError, UnicodeDecodeError):
                pass
        return out

    def scan(self, text: str) -> ScanResult:
        findings: dict[str, float] = {}
        if INVISIBLE.search(text):
            findings["hidden_characters"] = 0.5
        for variant in self._variants(text):
            for cat, rx, weight in COMPILED:
                if rx.search(variant):
                    findings[cat] = max(findings.get(cat, 0), weight)
        score = min(1.0, sum(findings.values()))
        return ScanResult(round(score, 2), score >= self.threshold, sorted(findings))


# --------------------------------------------------------------------- tool policy
@dataclass
class ToolDecision:
    call: dict
    allowed: bool
    reason: str = ""


class ToolPolicy:
    """Business rules enforced in code. Limits are per request in TOTAL, so splitting one big
    refund into several small calls doesn't work."""

    def __init__(self, max_refund: float = 50.0, allowed_email_domain: str = COMPANY_DOMAIN):
        self.max_refund = max_refund
        self.allowed_email_domain = allowed_email_domain

    def check_all(self, calls: list[dict], untrusted_content_present: bool) -> list[ToolDecision]:
        decisions, refunded = [], 0.0
        for call in calls:
            d = self.check(call, untrusted_content_present)
            if d.allowed and call.get("name") == "issue_refund":
                amount = float((call.get("arguments") or {}).get("amount", 0))
                if refunded + amount > self.max_refund:
                    d = ToolDecision(call, False, f"total refunds in one request would exceed {self.max_refund}")
                else:
                    refunded += amount
            decisions.append(d)
        return decisions

    def check(self, call: dict, untrusted_content_present: bool) -> ToolDecision:
        name, args = call.get("name"), call.get("arguments") or {}
        if name == "lookup_order":
            return ToolDecision(call, True)
        if untrusted_content_present:
            # A document may have planted this action: side effects need a human to confirm.
            return ToolDecision(call, False, "side-effecting tool while untrusted content is in context: needs human approval")
        if name == "issue_refund":
            try:
                amount = float(args.get("amount", 0))
            except (TypeError, ValueError):
                return ToolDecision(call, False, "invalid refund amount")
            if not 0 < amount <= self.max_refund:
                return ToolDecision(call, False, f"refund {amount} exceeds the {self.max_refund} limit")
            return ToolDecision(call, True)
        if name == "send_email":
            to = str(args.get("to", "")).strip().lower()
            if not to.endswith("@" + self.allowed_email_domain) or to.count("@") != 1:
                return ToolDecision(call, False, f"email to {to!r} is outside @{self.allowed_email_domain}")
            if _contains_secret(str(args)):
                return ToolDecision(call, False, "email body contains confidential data")
            return ToolDecision(call, True)
        return ToolDecision(call, False, f"unknown tool {name!r}")


# --------------------------------------------------------------------- output guard
URL_RE = re.compile(r"https?://[^\s)\]\"'>]+", re.I)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _contains_secret(text: str) -> bool:
    if _squash(CANARY) in _squash(text):  # catches "O R B I T - C A N A R Y ...", lower case, etc.
        return True
    if _squash(CANARY) in _squash(text[::-1]):
        return True
    for blob in B64.findall(text):
        try:
            if _squash(CANARY) in _squash(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore")):
                return True
        except ValueError:
            pass
    return False


def _system_prompt_overlap(text: str, n: int = 8) -> bool:
    """True if the answer copies any 8-word run from the system prompt."""
    words = re.findall(r"\w+", SYSTEM_PROMPT.lower())
    grams = {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)}
    out = re.findall(r"\w+", text.lower())
    return any(" ".join(out[i : i + n]) in grams for i in range(len(out) - n + 1))


@dataclass
class GuardResult:
    text: str
    blocked: bool
    reasons: list[str] = field(default_factory=list)


class OutputGuard:
    REFUSAL = "Sorry, I can't share that."

    def __init__(self, allowed_domains: tuple[str, ...] = (COMPANY_DOMAIN,)):
        self.allowed_domains = allowed_domains

    def check(self, text: str) -> GuardResult:
        reasons = []
        if _contains_secret(text):
            reasons.append("secret leak")
        if _system_prompt_overlap(text):
            reasons.append("system prompt leak")
        if reasons:
            return GuardResult(self.REFUSAL, True, reasons)
        cleaned = MD_IMAGE_RE.sub("[image removed]", text)  # images load automatically = zero-click exfiltration
        for url in URL_RE.findall(cleaned):
            host = (urlparse(url).hostname or "").lower()
            if not any(host == d or host.endswith("." + d) for d in self.allowed_domains):
                cleaned = cleaned.replace(url, "[link removed]")
        if cleaned != text:
            reasons.append("external link/image removed")
        return GuardResult(cleaned, False, reasons)


def apply_output_defenses(output: ModelOutput, guard: OutputGuard | None, policy: ToolPolicy | None,
                          untrusted_present: bool) -> tuple[ModelOutput, list[str]]:
    notes: list[str] = []
    calls = output.tool_calls
    if policy:
        decisions = policy.check_all(calls, untrusted_present)
        calls = [d.call for d in decisions if d.allowed]
        notes += [f"tool blocked: {d.reason}" for d in decisions if not d.allowed]
    text = output.text
    if guard:
        result = guard.check(text)
        text = result.text
        notes += result.reasons
    return ModelOutput(text, calls), notes
