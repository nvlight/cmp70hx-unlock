#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare the SEC2 window and DMA-queue counters between two EFI logs.

The A/B question is narrow: does `0x001C0004` at 0x840340/0x840370 change
between a locked boot and an unlocked one? Both runs must be produced by our
own code, because an externally taken dump (RWEverything, from Windows) is
read after the driver has already reinitialised the GPU, which is a
different state entirely and cannot be compared against EFI-time readings.

Usage:
    python out/tools/sec2-compare.py out/usb-log-sec2-unlocked.txt out/usb-log-sec2-locked.txt
"""

import io
import re
import sys

BADF_MASK = 0xBADF0000


def parse(path):
    """Return {'stages': [(tag, [(addr, val), ...])], 'dmq': {...}} for one log."""
    t = io.open(path, encoding='utf-8', errors='replace').read()
    lines = t.split('\n')

    stages = []
    order = []
    for l in lines:
        if 'SEC2W' not in l:
            continue
        body = l.split('SEC2W', 1)[1]
        tag = body.strip().split(' ')[0]
        pairs = re.findall(r'0x([0-9A-Fa-f]{8})=0x([0-9A-Fa-f]{8})', body)
        if tag not in order:
            order.append(tag)
            stages.append((tag, []))
        stages[[s[0] for s in stages].index(tag)][1].extend(
            (int(a, 16), int(v, 16)) for a, v in pairs)

    dmq = {'full': 0, 'idle': 0, 'last_full_cmd': None, 'last_idle_cmd': None}
    for l in lines:
        m = re.search(r'DMAQ\s+FULL timeout #(\d+) cmd=0x([0-9A-Fa-f]{8})', l)
        if m:
            dmq['full'] = int(m.group(1))
            dmq['last_full_cmd'] = int(m.group(2), 16)
        m = re.search(r'DMAQ\s+IDLE timeout #(\d+) cmd=0x([0-9A-Fa-f]{8})', l)
        if m:
            dmq['idle'] = int(m.group(1))
            dmq['last_idle_cmd'] = int(m.group(2), 16)

    # dmatrfcmd at each stage boundary, from the SEC2S summary lines
    summary = {}
    for l in lines:
        if 'SEC2S' not in l:
            continue
        tag = l.split('SEC2S', 1)[1].strip().split(' ')[0]
        m = re.search(r'BADF=(\d+)\s+live=(\d+)\s+dmatrfcmd=0x([0-9A-Fa-f]{8})'
                      r'\s+fullTo=(\d+)\s+idleTo=(\d+)', l)
        if m:
            summary[tag] = dict(badf=int(m.group(1)), live=int(m.group(2)),
                                dmatrfcmd=int(m.group(3), 16),
                                full_to=int(m.group(4)), idle_to=int(m.group(5)))

    return dict(stages=stages, dmq=dmq, summary=summary)


def live_words(stage_words):
    return [(a, v) for a, v in stage_words if (v & BADF_MASK) != BADF_MASK]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    pa, pb = sys.argv[1], sys.argv[2]
    A, B = parse(pa), parse(pb)

    print('=' * 78)
    print('A = %s' % pa)
    print('B = %s' % pb)
    print('=' * 78)

    print('\n--- DMA queue ---')
    print('%-22s %12s %12s' % ('', 'A', 'B'))
    for k, lbl in (('full', 'FULL timeouts'), ('idle', 'IDLE timeouts')):
        print('%-22s %12d %12d' % (lbl, A['dmq'][k], B['dmq'][k]))
    print('%-22s %12s %12s' % ('last FULL cmd',
          hex(A['dmq']['last_full_cmd']) if A['dmq']['last_full_cmd'] else '-',
          hex(B['dmq']['last_full_cmd']) if B['dmq']['last_full_cmd'] else '-'))

    print('\n--- SEC2 window: live (non-BADF) words per stage ---')
    for i in range(max(len(A['stages']), len(B['stages']))):
        sa = A['stages'][i] if i < len(A['stages']) else ('-', [])
        sb = B['stages'][i] if i < len(B['stages']) else ('-', [])
        la = dict(live_words(sa[1]))
        lb = dict(live_words(sb[1]))
        print('\nstage %d: A=%s  B=%s' % (i, sa[0], sb[0]))
        addrs = sorted(set(la) | set(lb))
        if not addrs:
            print('    (нет живых слов ни в A, ни в B)')
            continue
        for ad in addrs:
            va = la.get(ad)
            vb = lb.get(ad)
            mark = '  <-- ОТЛИЧАЕТСЯ' if va != vb else ''
            print('    0x%08x  A=%-12s B=%-12s%s' % (
                ad,
                hex(va) if va is not None else 'BADF',
                hex(vb) if vb is not None else 'BADF',
                mark))

    print('\n--- SEC2S summary ---')
    keys = []
    for d in (A['summary'], B['summary']):
        for k in d:
            if k not in keys:
                keys.append(k)
    print('%-24s %-26s %-26s' % ('stage', 'A', 'B'))
    for k in keys:
        a = A['summary'].get(k)
        b = B['summary'].get(k)
        fa = ('BADF=%d live=%d cmd=%s fTo=%d' %
              (a['badf'], a['live'], hex(a['dmatrfcmd']), a['full_to'])) if a else '-'
        fb = ('BADF=%d live=%d cmd=%s fTo=%d' %
              (b['badf'], b['live'], hex(b['dmatrfcmd']), b['full_to'])) if b else '-'
        print('%-24s %-26s %-26s' % (k[:24], fa, fb))
    return 0


if __name__ == '__main__':
    sys.exit(main())
