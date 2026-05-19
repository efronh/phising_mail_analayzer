#!/usr/bin/env python3

import argparse
import sys

from analyzer import PhishingEmailAnalyzer


def read_input(path):
    if path:
        f = open(path, "r", encoding="utf-8", errors="replace")
        text = f.read()
        f.close()
        return text
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(
        description="Rule-based phishing email analyzer (no ML)."
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Email text file. Reads stdin if you don't pass a file.",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS lookup for domains",
    )
    args = parser.parse_args()

    text = read_input(args.file)
    if text.strip() == "":
        print("Error: empty input.", file=sys.stderr)
        return 1

    analyzer = PhishingEmailAnalyzer(resolve_dns=not args.no_dns)
    result = analyzer.analyze(text)
    print(result.summary())

    if result.risk_level in ("LOW", "MEDIUM"):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
