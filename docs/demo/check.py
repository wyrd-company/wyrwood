#!/usr/bin/env python3
# ---
# relationships:
#   validates: overview
#   references: web-interface
# ---
"""Check local documentation links and the receipt from a real UI recording."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
RECEIPT = ROOT / 'docs/demo/screenshots.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs():
    paths = set()
    for pattern in ('internal/web/frontend/src/**/*', 'internal/web/frontend/public/*',
                    'internal/web/*.go', 'docs/demo/*.sh', 'docs/demo/check.py',
                    'internal/integration/testdata/Dockerfile',
                    'internal/web/frontend/index.html', 'internal/web/frontend/pnpm-lock.yaml'):
        paths.update(p for p in ROOT.glob(pattern) if p.is_file()
                     and '_test.go' not in p.name and '.test.' not in p.name
                     and p.relative_to(ROOT).as_posix() not in (
                         'internal/web/frontend/src/test-setup.ts',
                         'internal/web/frontend/src/render-test.tsx'))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}


def assets():
    # Only screenshots, not the independently maintained CLI animation or branding.
    return {str(p.relative_to(ROOT)): digest(p)
            for p in sorted((ROOT / 'docs/user/assets').glob('web-*.png'))}


def link_errors():
    errors = []
    for page in sorted((ROOT / 'docs/user').glob('*.md')):
        for target in re.findall(r'!?\[[^\]]*\]\(([^\s)]+)\)', page.read_text()):
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            path = page.parent / unquote(url.path) if url.path else page
            if not path.is_file():
                errors.append(f'{page.relative_to(ROOT)}: missing {target}')
            elif url.fragment and path.suffix == '.md':
                headings = re.findall(r'^#+\s+(.+)$', path.read_text(), re.M)
                anchors = [re.sub(r'[^\w\- ]', '', h.lower()).replace(' ', '-') for h in headings]
                if unquote(url.fragment) not in anchors:
                    errors.append(f'{page.relative_to(ROOT)}: missing anchor {target}')
    manifest = (ROOT / 'docs/user/docs.yml').read_text()
    for target in re.findall(r'assets/[\w.-]+', manifest):
        if not (ROOT / 'docs/user' / target).is_file():
            errors.append(f'docs.yml: missing {target}')
    for path in assets():
        if not (ROOT / path).read_bytes().startswith(b'\x89PNG\r\n\x1a\n'):
            errors.append(f'{path}: invalid PNG')
        if Path(path).name not in manifest:
            errors.append(f'{path}: absent from publishing manifest')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', action='store_true', help='used by record.sh after capture')
    args = parser.parse_args()
    errors = link_errors()
    current = {'inputs': inputs(), 'screenshots': assets()}
    if args.record and not errors:
        RECEIPT.write_text(json.dumps(current, indent=2, sort_keys=True) + '\n')
    elif not args.record:
        if not RECEIPT.is_file():
            errors.append('No screenshot receipt. Run task docs:screenshots.')
        else:
            recorded = json.loads(RECEIPT.read_text())
            for category, values in current.items():
                previous = recorded.get(category, {})
                changed = sorted(k for k in values.keys() | previous.keys()
                                 if values.get(k) != previous.get(k))
                if changed:
                    errors.append(f'Stale screenshot {category}: ' + ', '.join(changed)
                                  + '. Run task docs:screenshots and review the images.')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Documentation links, assets, and screenshot receipt OK.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
