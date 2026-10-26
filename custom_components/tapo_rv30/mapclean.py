"""The clean-up the Tapo app runs on a map's cell grid before drawing it: fill rooms, add a
wall boundary, merge wall runs into straight lines, fill gaps, combine with the robot's own
walls and rectify. Our own numpy version, giving the app's output cell for cell, plus the
app's choice of room colours.

Grids are indexed [y][x] in robot order. Cells outside the grid count as unknown. Each pass
reads the grid as it was when the pass started, except the line merge, which works in place
line by line as the app does."""
from __future__ import annotations

import numpy as np

NULL = -1      # unknown cell
_P = 8         # padding; no rule looks further than 6 cells
_SEEN = -2     # a ray cell beyond a wall
_CHUNK = 8192  # cells voted on at once
_CROSS = ((0, -1), (0, 1), (-1, 0), (1, 0))
_DIAG = ((-1, -1), (-1, 1), (1, -1), (1, 1))
# The app's 12 rays of 5 cells: columns x-1..x+1 down and up, rows y-1..y+1 right and left.
_RAYS = ([[(o, s * k) for k in range(1, 6)] for o in (-1, 0, 1) for s in (1, -1)]
         + [[(s * k, o) for k in range(1, 6)] for o in (-1, 0, 1) for s in (1, -1)])


def _box_offsets(x0, x1, y0, y1):
    """Offsets in the app's scan order: x outer, y inner."""
    return [(dx, dy) for dx in range(x0, x1 + 1) for dy in range(y0, y1 + 1)]


class _Cleaner:
    def __init__(self, wall: int, floor: int, room_lo: int, room_hi: int) -> None:
        self.wv, self.fv, self.lo, self.hi = wall, floor, room_lo, room_hi

    # Cell classes (NULL is none of them).
    def wall(self, a):
        return (a == self.wv) & (a != NULL)

    def room(self, a):
        return (a >= self.lo) & (a <= self.hi) & (a != NULL)

    def clean(self, a):
        return ((a == self.fv) | self.room(a)) & (a != NULL)

    def masks(self, g):
        """Padded grid and its padded wall, clean and unknown masks."""
        gp = np.pad(g, _P, constant_values=NULL)
        wp, cp = self.wall(gp), self.clean(gp)
        return gp, wp, cp, ~wp & ~cp

    # at(p, dx, dy)[y, x] is cell (x + dx, y + dy); ext grows the window by that many cells.
    @staticmethod
    def at(p, dx, dy, ext=0):
        h, w = p.shape[0] - 2 * _P, p.shape[1] - 2 * _P
        return p[_P - ext + dy:_P + h + ext + dy, _P - ext + dx:_P + w + ext + dx]

    def count(self, p, offsets, ext=0):
        return sum(self.at(p, dx, dy, ext).astype(np.int16) for dx, dy in offsets)

    def box(self, p, r=1, ext=0):
        return self.count(p, _box_offsets(-r, r, -r, r), ext)

    def diag_any(self, ext_mask):
        """True where any diagonal neighbour is True in a mask grown by 1 cell."""
        h, w = ext_mask.shape[0] - 2, ext_mask.shape[1] - 2
        return np.logical_or.reduce([ext_mask[1 + dy:1 + dy + h, 1 + dx:1 + dx + w] for dx, dy in _DIAG])

    def arms(self, wp, n):
        """Walls along the four arms of length n: left, up, right, down."""
        return [self.count(wp, [(sx * k, sy * k) for k in range(1, n + 1)]) for sx, sy in ((-1, 0), (0, -1), (1, 0), (0, 1))]

    def rays(self, tp, wp):
        """The app's 12 rays from a cell (columns x-1..x+1 up and down, rows y-1..y+1 left and
        right, 5 cells each): True where the ray meets tp before a wall."""
        hit = {}
        for dx, dy in _CROSS:
            blocked = got = np.False_
            for k in range(1, 6):
                wk, tk = self.at(wp, dx * k, dy * k, 1), self.at(tp, dx * k, dy * k, 1)
                got = got | (tk & ~wk & ~blocked)
                blocked = blocked | wk
            hit[dx, dy] = got
        h, w = tp.shape[0] - 2 * _P, tp.shape[1] - 2 * _P
        return ([hit[0, s][1:1 + h, 1 + o:1 + o + w] for o in (-1, 0, 1) for s in (1, -1)]
                + [hit[s, 0][1 + o:1 + o + h, 1:1 + w] for o in (-1, 0, 1) for s in (1, -1)])

    def line(self, wp, span, need, vertical):
        """The app's wall line test along one axis: a wall within span on each side, at most
        span cells apart, and at least need-1 walls among the 2*need+1 cells through it."""
        sx, sy = (0, 1) if vertical else (1, 0)
        lo = hi = np.int16(99)
        for k in range(span, 0, -1):
            lo = np.where(self.at(wp, -sx * k, -sy * k), np.int16(k), lo)
            hi = np.where(self.at(wp, sx * k, sy * k), np.int16(k), hi)
        run = self.count(wp, [(sx * k, sy * k) for k in range(-need, need + 1)])
        return (lo + hi - 1 <= span) & (run >= need - 1)

    def vote(self, g, cand, r):
        """The app's value vote for each candidate cell: (values, ys, xs), NULL for none. Each
        cell's vote only reads the grid, so they go in chunks to keep memory small."""
        gp = np.pad(g, _P, constant_values=NULL)
        ys, xs = np.nonzero(cand)
        flat, pw = gp.ravel(), gp.shape[1]
        base = ((ys + _P) * pw + xs + _P).astype(np.int32)
        res = np.full(len(ys), NULL, np.int16)
        for i in range(0, len(base), _CHUNK):
            res[i:i + _CHUNK] = self.vote_cells(flat, pw, base[i:i + _CHUNK], r)
        return res, ys, xs

    def vote_cells(self, flat, pw, base, r):
        def take(offsets, sel=slice(None)):   # (cells, offsets) values around each candidate
            return flat.take(base[sel, None] + np.array([dy * pw + dx for dx, dy in offsets], np.int32))

        n, s, w, e = take(_CROSS).T
        res = np.full(len(base), NULL, np.int16)
        a = (n == s) & self.room(n)
        b = ~a & (w == e) & self.room(w)
        res[a], res[b] = n[a], w[b]
        rest = np.flatnonzero(~a & ~b)
        if not len(rest):
            return res
        bx = take(_box_offsets(-r, r, -r, r), rest)
        # What each of the 12 rays sees before its first wall.
        rv = take([c for ray in _RAYS for c in ray], rest).reshape(len(rest), len(_RAYS), -1)
        hit = self.wall(rv)
        wall_at = np.where(hit.any(2), hit.argmax(2), rv.shape[2])[:, :, None]
        seen = np.where(np.arange(rv.shape[2]) >= wall_at, _SEEN, rv).reshape(len(rest), -1)
        roomy = self.room(bx).any(1)
        # No room within reach: floor if there is floor and a ray finds floor, else nothing.
        ok = ~roomy & self.clean(bx).any(1) & (seen == self.fv).any(1)
        res[rest[ok]] = self.fv
        mixed = rest[roomy]
        if len(mixed):
            near_room = self.room(n[mixed]) | self.room(s[mixed]) | self.room(w[mixed]) | self.room(e[mixed])
            res[mixed] = self.vote_rooms(lambda offsets: take(offsets, mixed), bx[roomy], seen[roomy], r, near_room)
        return res

    def vote_rooms(self, take, bx, seen, r, near_room):
        size = len(near_room)
        rows = np.arange(size)
        # Clean values in the boxes get codes 1.. (0 for anything else), and vis[i, code] says
        # whether a ray from candidate i reaches that value.
        values = np.concatenate(([NULL], np.unique(bx[self.clean(bx)])))
        lut = np.zeros(max(int(bx.max()), int(seen.max()), 0) + 3, np.intp)
        lut[values[1:] + 2] = np.arange(1, len(values))
        nv = len(values)
        vis = np.zeros((size, nv), bool)
        vis.ravel()[(rows * nv)[:, None] + lut[seen + 2]] = True
        vis[:, 0] = False

        # Quadrants: a quadrant whose rooms agree (the centre may differ unless it comes
        # first); a full one wins at once, else the fullest one a ray can reach.
        full = (r + 1) ** 2 - 1
        best = np.full(size, NULL, np.int16)
        best_n = np.zeros(size, int)
        done = np.zeros(size, bool)
        for (x0, x1), (y0, y1) in (((-r, 0), (-r, 0)), ((0, r), (-r, 0)), ((-r, 0), (0, r)), ((0, r), (0, r))):
            cells = _box_offsets(x0, x1, y0, y1)
            q = take(cells)
            rm = self.room(q)
            first = rm.argmax(1)
            v = q[rows, first]
            other = rm & (q != v[:, None]) & (np.arange(len(cells)) > first[:, None])
            other[:, cells.index((0, 0))] = False
            ok = rm.any(1) & ~other.any(1) & ~done
            k = (rm & (q == v[:, None])).sum(1)
            now = ok & (k == full)
            up = ok & ~now & (k > best_n) & vis[rows, lut[v + 2]]
            best[now | up] = v[now | up]
            best_n[up] = k[up]
            done |= now
        # Else the commonest clean value in the box a ray can reach (later first sight wins ties).
        left = np.flatnonzero(best == NULL)
        if len(left):
            m, nl = bx.shape[1], len(left)
            slot = (np.arange(nl) * nv)[:, None] + lut[bx[left] + 2]
            count = np.bincount(slot.ravel(), minlength=nl * nv).reshape(nl, nv)
            first = np.zeros(nl * nv, int)
            for j in range(m - 1, -1, -1):
                first[slot[:, j]] = j
            first = first.reshape(nl, nv)
            ok = vis[left] & (count > 0) & (~near_room[left][:, None] | self.room(values))
            score = np.where(ok, count * (m + 1) + first, -1)
            best[left] = np.where(score.max(1) >= 0, values[score.argmax(1)], NULL)
        return best

    @staticmethod
    def put(g, vals, ys, xs, skip_same=False):
        ok = vals != NULL
        if skip_same:
            ok &= vals != g[ys, xs]
        g = g.copy()
        g[ys[ok], xs[ok]] = vals[ok]
        return g

    def lone_walls(self, g):
        """Walls with no clean cell in their 3x3 become unknown."""
        _, wp, cp, _ = self.masks(g)
        return np.where(self.at(wp, 0, 0) & (self.box(cp) == 0), NULL, g)

    # The stages, in the order the app chains them.
    def run(self, src):
        g = np.where(self.clean(src), src, NULL).astype(np.int16)
        g = self.room_filling(g)
        g = self.add_boundary(g, src)
        g = self.merge_boundary(g)
        g = self.space_filling(g)
        g = self.combine_boundary(g, src)
        return self.rectify_boundary(g)

    def room_filling(self, g):
        _, _, cp, _ = self.masks(g)
        g = self.put(g, *self.vote(g, ~self.room(g) & (self.box(cp) > 0), 1))
        _, _, cp, up = self.masks(g)
        return np.where(self.at(cp, 0, 0) & (self.box(up) > 0), NULL, g)

    def add_boundary(self, g, src):
        """Unknown cells next to clean ones become wall where the robot saw wall or wall arms."""
        _, _, cp, up = self.masks(g)
        sw = np.pad(self.wall(src), _P)
        arms = self.arms(sw, 3)
        full = [sum((a >= k).astype(int) for a in arms) for k in (1, 2, 3)]
        edge = self.at(sw, 0, 0) | (full[2] > 1) | ((full[0] > 2) & (full[1] > 1) & (full[2] > 0))
        return np.where(self.at(up, 0, 0) & (self.box(cp) > 0) & edge, self.wv, g)

    def merge_boundary(self, g):
        g = g.copy()
        self.merge_lines(g.T)
        self.merge_lines(g)
        return g

    def space_filling(self, g):
        _, wp, cp, _ = self.masks(g)
        open_box = (self.box(cp, ext=1) >= 6) & (self.box(wp, ext=1) == 0)
        rays = sum(r.astype(np.int8) for r in self.rays(cp, wp))
        cand = ~self.at(wp, 0, 0) & (((self.count(cp, _CROSS) > 0) & self.diag_any(open_box)) | (rays >= 3))
        g = self.put(g, *self.vote(g, cand, 2), skip_same=True)
        _, _, _, up = self.masks(g)
        g = self.put(g, *self.vote(g, self.at(up, 0, 0) & (self.box(up) < 3), 1))
        # Clean specks among unknown are dropped.
        _, wp, cp, up = self.masks(g)
        thin = self.count(cp, _CROSS) < 2
        g = np.where(self.at(cp, 0, 0) & (self.box(up) > 3) & ((self.count(wp, _CROSS) == 0) | thin), NULL, g)
        _, _, cp, up = self.masks(g)
        return np.where(self.at(cp, 0, 0) & (self.box(up) > 0) & (self.count(cp, _CROSS) < 2), NULL, g)

    def combine_boundary(self, g, src):
        """Put back the robot's own walls, unless they sit in solid non-clean area."""
        own = self.lone_walls(np.where(self.wall(src) | self.clean(src), src, NULL))
        _, wp, cp, _ = self.masks(own)
        solid = self.box(~cp, ext=1) == 9
        return np.where(self.at(wp, 0, 0) & ~self.diag_any(solid), self.wv, g)

    def rectify_boundary(self, g):
        _, wp, cp, up = self.masks(g)
        line = self.line(wp, 3, 4, True) | self.line(wp, 3, 4, False)
        g = np.where(self.at(cp, 0, 0) & (self.count(up, _CROSS) > 0) & line, self.wv, g)
        g = self.lone_walls(g)
        # Wall corners near unknown, and unknown cells at wall stubs, become wall.
        _, wp, _, up = self.masks(g)
        left, top, right, down = (a == 5 for a in self.arms(wp, 5))
        corner = (self.box(up) > 1) & (top | down) & (left | right)
        stub = (self.at(up, 0, 0) & (sum((a >= 3).astype(int) for a in self.arms(wp, 3)) > 0)
                & (sum((a >= 3).astype(int) for a in self.arms(wp, 4)) > 1))
        g = np.where(corner | stub, self.wv, g)
        # Unknown cells in a short wall line with known cells and clean beside it.
        _, wp, cp, up = self.masks(g)
        gap = False
        for vertical in (False, True):
            sx, sy = (1, 0) if vertical else (0, 1)
            known = ~self.at(up, -sx, -sy) | ~self.at(up, sx, sy)
            beside = self.count(cp, [(sx * side + sy * k, sy * side + sx * k) for side in (-1, 1) for k in range(-3, 4)]) > 0
            gap = gap | (known & beside & self.line(wp, 2, 6, vertical))
        return np.where(self.at(up, 0, 0) & gap, self.wv, g)

    # mergeBoundary on lines[pos, k] (columns when given the transposed grid).
    def merge_lines(self, lines):
        npos, length = lines.shape
        walls = self.wall(lines)

        def is_wall(p, k):
            return 0 <= p < npos and 0 <= k < length and bool(walls[p, k])

        for i in range(npos - 2):
            segs = []
            for p in range(i, i + 3):
                if p > i and not segs:
                    break
                edges = np.flatnonzero(np.diff(np.concatenate(([0], walls[p].astype(np.int8), [0]))))
                segs += [(p, int(s), int(e) - 1) for s, e in zip(edges[::2], edges[1::2]) if e - s >= 2 and e < length]
            if len(segs) < 2:
                continue
            segs.sort(key=lambda d: d[1])
            groups, cur = [], []
            for prev, nxt in zip(segs, segs[1:]):
                if self.joins(prev, nxt):
                    if prev in cur:
                        cur.append(nxt)
                    else:
                        if self.keeps(cur, is_wall):
                            groups.append(cur)
                        cur = [prev, nxt]
            if self.keeps(cur, is_wall):
                groups.append(cur)
            for grp in groups:
                weight: dict[int, int] = {}
                for p, s, e in grp:
                    weight[p] = weight.get(p, 0) + e - s
                target = max(weight, key=weight.get)
                acc = grp[0]
                for seg in grp[1:]:
                    for p, s, e in (acc, seg):
                        if p != target:
                            self.shift(lines, walls, p, s, e, target, is_wall)
                    lines[target, acc[1]:seg[2] + 1] = self.wv
                    walls[target, acc[1]:seg[2] + 1] = True
                    acc = (target, acc[1], seg[2])

    @staticmethod
    def joins(a, b):
        """Two runs, sorted by start, belong to one wall."""
        if b[1] - a[2] > 2 or max(a[2], b[2]) - a[1] + 1 < 4:
            return False
        return abs(b[0] - a[0]) < 2 or not (b[1] == a[1] or b[2] == a[2])

    @staticmethod
    def keeps(grp, is_wall):
        """A group is merged if it spans 25+ cells or no other wall line meets its ends."""
        if not grp:
            return False
        s0, p0 = min(((s, p) for p, s, _ in grp), key=lambda t: t[0])
        e1, p1 = max(((e, p) for p, _, e in grp), key=lambda t: t[0])
        if e1 - s0 >= 25:
            return True
        for pos, k, own in ((p0 - 1, s0 - 1, p0), (p0 + 1, s0 - 1, p0), (p1 - 1, e1 + 1, p1), (p1 + 1, e1 + 1, p1)):
            hits = {kk for pp in (pos - 1, pos, pos + 1) for kk in (k - 1, k, k + 1) if pp != own and is_wall(pp, kk)}
            if len(hits) > 1:
                return False
        return True

    def shift(self, lines, walls, p, s, e, target, is_wall):
        """Clear a run on its line and every line up to (not including) target, keeping each
        end as wall where the line behind the run had wall there."""
        step = 1 if p <= target else -1
        ends = [(s, is_wall(p - step, s)), (e, is_wall(p - step, e))]
        for q in range(p, target, step):
            lines[q, s + 1:e] = NULL
            walls[q, s + 1:e] = False
            for k, keep in ends:
                lines[q, k] = self.wv if keep else NULL
                walls[q, k] = keep


def clean_grid(grid, wall: int = 0, floor: int = 255, rooms: tuple[int, int] = (1, 100)) -> np.ndarray:
    """The app's cleaned copy of a [y][x] grid of cell values: wall, floor and room values,
    NULL for anything else."""
    g = np.asarray(grid, dtype=np.int16)
    if g.ndim != 2:
        raise ValueError(f"a map grid has 2 dimensions, not {g.ndim}")
    if not g.size:
        return np.full(g.shape, NULL, np.int16)
    return _Cleaner(wall, floor, rooms[0], rooms[1]).run(g)


def _byte(value, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255 else default


def grid_values(map_data: dict) -> tuple[int, int, tuple[int, int]]:
    """Wall value, floor value and room value range from a map's bit_list, as the app reads
    them (0, 255 and 1..100 when missing; the range never starts below 1)."""
    bits = map_data.get("bit_list")
    bits = bits if isinstance(bits, dict) else {}
    area = bits.get("auto_area")
    ids = [v for v in area if isinstance(v, int) and not isinstance(v, bool)] if isinstance(area, list) else []
    rooms = (max(1, min(ids)), max(ids)) if ids else (1, 100)
    return _byte(bits.get("barrier"), 0), _byte(bits.get("clean"), 255), rooms


def _hash_order(keys: list[int]) -> list[int]:
    """The order a java.util.HashMap iterates small int keys put in this order: by bucket, then
    insertion. Its table starts at 16 slots and doubles past 3/4 full, or when a bucket passes
    8 keys while under 64 slots."""
    slots = 16
    for size, k in enumerate(keys, 1):
        if slots < 64 and sum(j % slots == k % slots for j in keys[:size]) > 8:
            slots *= 2
        if size > slots * 3 // 4:
            slots *= 2
    return sorted(keys, key=lambda k: k % slots)


def room_colours(cleaned, rooms: tuple[int, int] = (1, 100), preset: dict | None = None) -> dict[int, int]:
    """The app's colour (1-5) for each room in a cleaned grid. A room keeps its own colour from
    the map (preset, 1-5); the rest are picked greedily so touching rooms differ: rooms with
    the most neighbours first, from colours 1-4 least recently picked first, then 5, then
    (id - 1) % 5 + 1. Rooms touch when one has a cell in the other's 3x3, counted on flat
    cell indices as the app does, so a row end touches the next row's start."""
    g = np.asarray(cleaned)
    if g.ndim != 2:
        raise ValueError(f"a map grid has 2 dimensions, not {g.ndim}")
    if not g.size:
        return {}
    w = g.shape[1]
    flat = g.ravel()
    is_room = (flat >= rooms[0]) & (flat <= rooms[1]) & (flat != NULL)
    ids = np.unique(flat[is_room]).tolist()
    preset = preset or {}
    colour = {rid: preset[rid] for rid in ids if preset.get(rid) in (1, 2, 3, 4, 5)}
    if len(colour) == len(ids):
        return colour

    cells = np.flatnonzero(is_room).astype(np.int32)
    values, code = np.unique(flat[cells], return_inverse=True)   # code: the room of each cell
    x, y = cells % w, cells // w
    # Each room's box, for the app's test across a row end (the other room's box, grown by 1).
    box = [np.full(len(values), fill, np.int32) for fill in (w, -1, g.shape[0], -1)]
    np.minimum.at(box[0], code, x)
    np.maximum.at(box[1], code, x)
    np.minimum.at(box[2], code, y)
    np.maximum.at(box[3], code, y)
    room_at = np.full(flat.size, -1, np.int16)
    room_at[cells] = code
    found = []
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            other = cells + (dy * w + dx)
            ok = (other >= 0) & (other < flat.size)
            b = np.where(ok, room_at[np.where(ok, other, 0)], -1)
            ok &= (b >= 0) & (b != code)
            wraps = (x + dx < 0) | (x + dx >= w)
            if wraps.any():
                bw = np.where(ok & wraps, b, 0)
                inside = ((box[0][bw] - 1 <= x) & (x <= box[1][bw] + 1)
                          & (box[2][bw] - 1 <= y) & (y <= box[3][bw] + 1))
                ok &= ~wraps | inside
            found.append(code[ok].astype(np.int32) * len(values) + b[ok])
    pairs = {(int(values[p // len(values)]), int(values[p % len(values)])) for p in np.unique(np.concatenate(found))}
    # The app walks its rooms in hash map order and clears a room's set when it reaches it,
    # so a link made earlier only survives if the test also holds from this room's side.
    first = np.full(len(values), flat.size, np.int32)
    np.minimum.at(first, code, cells)
    walk = _hash_order(values[np.argsort(first)].tolist())
    near: dict[int, set[int]] = {rid: set() for rid in ids}
    for a in walk:
        near[a] = set()
        for b in walk:
            if b != a and b not in near[a] and (a, b) in pairs:
                near[a].add(b)
                near[b].add(a)

    free = [1, 2, 3, 4]
    for rid in sorted(ids, key=lambda r: (r not in colour, -len(near[r]), r)):
        if rid in colour:
            continue
        taken = {colour[n] for n in near[rid] if n in colour}
        pick = next((c for c in free if c not in taken), None)
        if pick is not None:
            free.remove(pick)
            free.append(pick)
        else:
            pick = 5 if 5 not in taken else (rid - 1) % 5 + 1
        colour[rid] = pick
    return colour
