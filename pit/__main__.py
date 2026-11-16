"""Run the prompt-injection suite.

    python -m pit                                   # worst-case model, offline
    python -m pit --model groq --trials 3           # a real model (needs GROQ_API_KEY)
    python -m pit --max-asr 0.10                    # CI gate: fail if ASR with all defenses > 10%
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .runner import CONFIGS, OpenAICompatibleModel, WorstCaseModel, load_cases, markdown_report, run_suite, save_json, summarize

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    p = argparse.ArgumentParser(description="Prompt injection test suite")
    p.add_argument("--model", choices=["worst-case", "groq"], default="worst-case")
    p.add_argument("--attacks", default=str(ROOT / "attacks"))
    p.add_argument("--configs", nargs="+", default=None, choices=list(CONFIGS))
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--report", default=None, help="write a markdown report here")
    p.add_argument("--json", default=None, help="write raw results here")
    p.add_argument("--max-asr", type=float, default=None, help="exit 1 if overall ASR with all defenses is higher")
    args = p.parse_args(argv)

    if args.model == "groq":
        key = os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY")
        if not key:
            print("Set GROQ_API_KEY to test a real model.", file=sys.stderr)
            return 2
        model = OpenAICompatibleModel(os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"), key,
                                      os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"))
        configs = args.configs or list(CONFIGS)
    else:
        model = WorstCaseModel()
        # Spotlighting only changes how a real model reads the prompt; a hijacked model ignores it.
        configs = args.configs or [c for c in CONFIGS if c != "spotlighting"]

    cases = load_cases(args.attacks)
    results = run_suite(cases, model, configs, args.trials)
    report = markdown_report(results, model.name)
    print(report)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(report, encoding="utf-8")
    if args.json:
        save_json(results, args.json)
    if args.max_asr is not None:
        asr = summarize(results).get("all", {}).get("overall_asr", 1.0)
        if asr > args.max_asr:
            print(f"FAIL: overall ASR with all defenses {asr:.0%} > {args.max_asr:.0%}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
