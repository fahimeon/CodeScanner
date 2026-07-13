"""Unit tests for detect_duplicates.py — staged MinHash/LSH clustering (offline)."""

import json

import detect_duplicates as dj


def _files(n, prefix="src/f"):
    return [f"{prefix}{i}.ts" for i in range(n)] + ["package.json", "README.md"]


def _sh(files, pkg_text=None):
    return dj.shingle_set(dj.repo_signature(files, pkg_text))


# --------------------------------------------------------------------------- #
# Similarity primitives
# --------------------------------------------------------------------------- #
def test_jaccard():
    assert dj.jaccard(frozenset("ab"), frozenset("ab")) == 1.0
    assert dj.jaccard(frozenset("ab"), frozenset("cd")) == 0.0
    assert dj.jaccard(frozenset("abcd"), frozenset("abce")) == 3 / 5


def test_repo_signature_and_shingles():
    sig = dj.repo_signature(["src/a.ts", "package.json"],
                            json.dumps({"name": "myapp", "dependencies": {"next": "1"}}))
    sh = dj.shingle_set(sig)
    assert "src/a.ts" in sh and "dep::next" in sh and "name::myapp" in sh


def test_minhash_is_deterministic_and_estimates_jaccard():
    perms = dj.minhash_permutations(128, seed=20260711)
    a = _sh(_files(30)); b = _sh(_files(30) + ["src/x.ts"])
    sa1 = dj.minhash_signature(a, perms)
    sa2 = dj.minhash_signature(a, perms)
    assert sa1 == sa2                                    # deterministic
    sb = dj.minhash_signature(b, perms)
    est = dj.estimated_jaccard(sa1, sb)
    exact = dj.jaccard(a, b)
    assert abs(est - exact) < 0.15                       # MinHash estimates Jaccard


# --------------------------------------------------------------------------- #
# Staged clustering
# --------------------------------------------------------------------------- #
def test_cluster_near_duplicates_via_lsh():
    sh = {"o/a": _sh(_files(20)), "o/b": _sh(_files(20) + ["src/extra.ts"]),
          "o/c": _sh(_files(20, prefix="lib/g"))}
    clusters = dj.cluster_repos(sh, threshold=0.85)
    sizes = sorted(len(g) for g in clusters)
    assert sizes == [1, 2]
    pair = [g for g in clusters if len(g) == 2][0]
    assert set(pair) == {"o/a", "o/b"}


def test_exact_identical_tiny_trees_cluster():
    sh = {"o/d": _sh(["a.ts", "b.ts"]), "o/e": _sh(["a.ts", "b.ts"]),
          "o/f": _sh(["a.ts", "z.ts"])}
    clusters = dj.cluster_repos(sh, threshold=0.85)
    twos = [g for g in clusters if len(g) == 2]
    assert len(twos) == 1 and set(twos[0]) == {"o/d", "o/e"}


def test_representative_is_outcome_independent_lexicographic():
    assert dj.choose_representative(["o/z", "o/a", "o/m"]) == "o/a"


def test_build_records_flags_non_representatives():
    clusters = [["o/a", "o/b"], ["o/solo"]]
    sh = {"o/a": frozenset("abc"), "o/b": frozenset("abc"), "o/solo": frozenset("xy")}
    rows = dj.build_duplicate_records(clusters, sh)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/a"]["is_representative"] is True and by["o/a"]["is_duplicate"] is False
    assert by["o/b"]["is_duplicate"] is True and by["o/b"]["duplicate_of"] == "o/a"
    assert by["o/solo"]["cluster_size"] == 1 and by["o/solo"]["is_duplicate"] is False


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def test_detect_all_end_to_end(tmp_path):
    trees = {"o/a": (_files(20), None), "o/b": (_files(20) + ["src/x.ts"], None),
             "o/c": (_files(20, prefix="lib/g"), None), "o/gone": None}

    def fingerprint_fn(full, branch, url):
        return trees[full]

    candidates = [{"repository_full_name": k} for k in trees]
    metadata = {k: {"repository_full_name": k, "fetch_status": "OK", "default_branch": "main"}
                for k in ("o/a", "o/b", "o/c")}
    metadata["o/gone"] = {"repository_full_name": "o/gone", "fetch_status": "NOT_FOUND"}
    rows, clusters = dj.detect_all(candidates, metadata, {}, tmp_path / "fp",
                                   tmp_path / "log.jsonl", fingerprint_fn,
                                   dj.DEFAULT_JACCARD_THRESHOLD)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/b"]["is_duplicate"] is True and by["o/b"]["duplicate_of"] == "o/a"
    assert by["o/a"]["is_representative"] is True          # lexicographically first
    assert by["o/gone"]["status"] == "UNAVAILABLE"
