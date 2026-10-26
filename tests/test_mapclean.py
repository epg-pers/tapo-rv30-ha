"""The app's map clean-up and room colours (mapclean). Grids are made up. Rows are listed y=0
first: '#' wall (0), '+' floor (255), '?' unknown (127), digits rooms, '.' empty (NULL)."""
import numpy as np
import pytest

from custom_components.tapo_rv30.mapclean import NULL, _Cleaner, clean_grid, grid_values, room_colours

CELLS = {"#": 0, "+": 255, "?": 127, ".": NULL}


def grid(rows):
    return np.array([[CELLS[c] if c in CELLS else int(c) for c in row] for row in rows], np.int16)


def text(g):
    names = {0: "#", 255: "+", 127: "?", NULL: "."}
    return [''.join(names.get(int(v), str(int(v))) for v in row) for row in g]


def kept(rows):
    """A stage's input: the clean cells of a robot grid, the rest empty."""
    g = grid(rows)
    return np.where((g == 255) | ((g >= 1) & (g <= 100)), g, NULL).astype(np.int16)


C = _Cleaner(0, 255, 1, 100)


def test_room_filling_fills_holes_and_trims_edges_next_to_unknown():
    rows = ["???????", "?11111?", "?11+11?", "?1+++1?", "?11+11?", "?11111?", "???????"]
    assert text(C.room_filling(kept(rows))) == [
        ".......", ".11111.", ".11111.", ".11111.", ".11111.", ".11111.", "......."]


def test_room_filling_splits_a_floor_strip_between_rooms():
    rows = ["???????", "?11+22?", "?11+22?", "?11+22?", "?11+22?", "?11+22?", "???????"]
    assert text(C.room_filling(kept(rows)))[1:6] == [".11122."] * 5


def test_add_boundary_puts_back_the_robots_walls_round_clean_space():
    rows = ["???????", "?#####?", "?#+++#?", "?#+++#?", "?#+++#?", "?#####?", "???????"]
    assert text(C.add_boundary(kept(rows), grid(rows))) == [
        ".......", ".#####.", ".#+++#.", ".#+++#.", ".#+++#.", ".#####.", "......."]


@pytest.mark.parametrize(("rows", "want"), [
    (["+######+++++++", "+++++++######+"], ["+############+", "+++++++......+"]),
    (["+####++++++", "++++####+++"], ["+#######+++", "++++....+++"]),
])
def test_merge_boundary_straightens_staggered_wall_runs(rows, want):
    g = grid(["+" * len(rows[0])] * 2 + rows + ["+" * len(rows[0])] * 2)
    assert text(C.merge_boundary(g))[2:4] == want


def test_merge_boundary_leaves_runs_reaching_the_grid_edge():
    g = grid(["++++++++++++"] * 2 + ["######++++++", "++++++######"] + ["++++++++++++"] * 2)
    assert np.array_equal(C.merge_boundary(g), g)


def test_space_filling_fills_a_hole_and_drops_exposed_corners():
    rows = ["+++++++", "+++++++", "+++?+++", "++???++", "+++?+++", "+++++++", "+++++++"]
    assert text(C.space_filling(kept(rows))) == [
        ".+++++.", "+++++++", "+++++++", "+++++++", "+++++++", "+++++++", ".+++++."]


def test_combine_boundary_restores_walls_inside_clean_space():
    rows = ["+++++", "+#+++", "+++++", "+++#+", "+++++"]
    assert text(C.combine_boundary(kept(rows), grid(rows))) == rows


def test_rectify_boundary_drops_a_wall_with_no_clean_cell_round_it():
    rows = ["???????", "?.....?", "?..#..?", "?.....?", "+++++++", "+++++++", "#######"]
    out = text(C.rectify_boundary(grid(rows)))
    assert out[2] == "?.....?" and out[4:] == rows[4:]


# Whole clean-ups from synthetic grids, checked against the app.
GOLDEN = [
    ((
        "????????##33##?",
        "????????##333#3",
        "???+????##33##?",
        "????????##33##?",
        "############3##",
        "????????######?",
        "???????????111?",
        "???????????#???",
        "#######????1???",
        "113111#????????",
        "+++++++++++++++",
        "111111#?????111",
        "11111+#????????",
        "1111#1#????????",
        "#######????????",
    ), (
        ".........#####.",
        ".........#333#.",
        ".........#33##.",
        ".........#33##.",
        ".........#3#3#.",
        ".........#1###.",
        ".........11111.",
        ".........11#111",
        "#######11111111",
        "111111#11111111",
        "111111111111111",
        "111111#1111111.",
        "111111#1111111.",
        "1111#1#........",
        "#######........",
    )),
    ((
        "+?+?+++?+?+++###++",
        "?++?+++++++++###+?",
        "+++?+++++++++###++",
        "+++++++?+++++###+?",
        "+++?+++++++++###++",
        "?+?+######+#######",
        "++++##+++++#######",
        "?+?+##+++++#######",
        "?+?+##+++++++###++",
        "++++##+++++++###+?",
        "++++++++??+++###++",
        "++++++++?+++++?+++",
    ), (
        "..+++++++++++#....",
        ".++++++++++++#.#..",
        "+++++++++++++#.#++",
        "+++++++++++++#.#++",
        "+++++++++++++#.#++",
        "++++######+++#.###",
        "++++##+++++#+#.#..",
        "++++##+++++++#.###",
        "++++##+++++++#.#++",
        "++++##+++++++#.#++",
        ".++++++++++++#.#..",
        "..++++++++++......",
    )),
    ((
        "#???1???##++?+2",
        "#??#????#+++++2",
        "#???+???#+++++2",
        "#????2??#+++2+2",
        "#???????#++2++#",
        "+?????#?######2",
        "#?????????3???+",
        "#+???+????????2",
        "#????2??###2##2",
        "#??####3######?",
        "#??#33333#11112",
        "#??#######11112",
        "#???????##11112",
    ), (
        "........##222..",
        "...#111.#22222.",
        "...22222#222222",
        "...22222#222222",
        "....2222#22222#",
        "....2222######.",
        "#..2222233322#.",
        "#++222323#333#.",
        "#++22332#.#2##2",
        "...####3######1",
        "...#3333#.#1111",
        "...######.#111.",
        "...............",
    )),
]


@pytest.mark.parametrize(("rows", "want"), GOLDEN)
def test_clean_grid_matches_the_app(rows, want):
    assert text(clean_grid(grid(rows))) == list(want)


def test_clean_grid_edge_cases():
    assert clean_grid(np.zeros((0, 4))).shape == (0, 4)
    with pytest.raises(ValueError):
        clean_grid(np.zeros(4))
    with pytest.raises(ValueError):
        room_colours(np.zeros((2, 2, 2)))
    assert (clean_grid(grid(["+"])) == NULL).all()
    # Other values for wall, floor and rooms, as a map's bit_list can give them.
    g = np.array([[9, 9, 9, 9, 9]] + [[9, 7, 7, 7, 9]] * 3 + [[9, 9, 9, 9, 9]], np.int16)
    assert clean_grid(g, wall=9, floor=7, rooms=(20, 30))[2, 2] == 7


def test_grid_values_from_bit_list():
    assert grid_values({}) == (0, 255, (1, 100))
    assert grid_values({"bit_list": {"barrier": 0, "clean": 255, "auto_area": [0, 100]}}) == (0, 255, (1, 100))
    assert grid_values({"bit_list": {"barrier": 3, "clean": 200, "auto_area": [40, 10, 20]}}) == (3, 200, (10, 40))
    assert grid_values({"bit_list": {"barrier": 999, "clean": "x", "auto_area": "y"}}) == (0, 255, (1, 100))


@pytest.mark.parametrize(("rows", "preset", "want"), [
    # A row of rooms: most neighbours first, colours 1-4 least recently used first.
    (["111222333444555666"], {}, {1: 2, 2: 1, 3: 2, 4: 3, 5: 4, 6: 1}),
    # The map's own colours stay; the rest avoid them.
    (["111222333444555666"], {2: 3, 5: 2}, {1: 2, 2: 3, 3: 1, 4: 3, 5: 2, 6: 4}),
    (["12", "34"], {1: 1, 2: 0}, {1: 1, 2: 2, 3: 3, 4: 4}),
    # Diagonals touch; 9 rooms need the fifth colour nowhere here.
    (["1234", "5678", "9123"], {}, {1: 4, 2: 1, 3: 4, 4: 1, 5: 3, 6: 2, 7: 3, 8: 2, 9: 1}),
    # Row ends touch the next row's start, but only from one side, and the app's walk clears
    # links made from the other side: 2 ends up with one neighbour, so 4 is coloured first.
    (["....2", "2....", "4....", "4....", "1....", "1...2", ".....", ".....", "22..."], {}, {1: 1, 2: 3, 4: 2}),
])
def test_room_colours_match_the_app(rows, preset, want):
    assert room_colours(grid(rows), (1, 100), preset) == want


@pytest.mark.parametrize(("rows", "preset", "want"), [
    # Colours 1-4 all next door: 5.
    (["12", "93", "4."], {1: 1, 2: 2, 3: 3, 4: 4}, {9: 5}),
    # All five next door: (id - 1) % 5 + 1.
    (["123", "475", "..."], {1: 1, 2: 2, 3: 3, 4: 4, 5: 5}, {7: 2}),
    # A colour outside 1-5 is no colour: room 5 is picked like any other.
    (["123", "475", "..."], {1: 1, 2: 2, 3: 3, 4: 4, 5: 6}, {5: 1, 7: 5}),
])
def test_room_colours_fall_back_to_five_then_the_id(rows, preset, want):
    got = room_colours(grid(rows), (1, 100), preset)
    assert {r: got[r] for r in want} == want
    assert room_colours(grid(["...."]), (1, 100), {}) == {}
