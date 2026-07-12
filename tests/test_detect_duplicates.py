"""Unit tests for detect_duplicates.py — fingerprint, clustering, representative (offline)."""

import json

import detect_duplicates as dj


def _files(n, prefix="src/f"):
    return [f"{prefix}{i}.ts" for i in range(n)] + ["package.json", "README.md"]


# --------------------------------------------------------------------------- #
# Similarity primitives
# --------------------------------------------------------------------------- #
def test_jaccard():
    assert dj.jaccard(frozenset("ab"), frozenset("ab")) == 1.0
    assert dj.jaccard(frozenset("ab"), frozenset("cd")) == 0.0
    assert dj.jaccard(frozenset(), frozenset()) == 1.0
    assert dj.jaccard(frozenset("abcd"), frozenset("abce")) == 3 / 5


def test_repo_signature():
    sig = dj.repo_signature(["src/a.ts", "package.json"],
                            json.dumps({"name": "myapp", "dependencies": {"next": "1"}}))
    assert "src/a.ts" in sig["paths"]
    assert sig["name"] == "myapp"
    assert "next" in sig["deps"]


# --------------------------------------------------------------------------- #
# Clustering
# --------------------------------------------------------------------------- #
def test_cluster_near_duplicates_together():
    a = dj.repo_signature(_files(20), None)
    b = dj.repo_signature(_files(20) + ["src/extra.ts"], None)   # ~0.96 Jaccard with a
    c = dj.repo_signature(_files(20, prefix="lib/g"), None)      # disjoint paths
    clusters = dj.cluster_signatures({"o/a": a, "o/b": b, "o/c": c})
    sizes = sorted(len(g) for g in clusters)
    assert sizes == [1, 2]
    pair = [g for g in clusters if len(g) == 2][0]
    assert set(pair) == {"o/a", "o/b"}


def test_tiny_trees_only_cluster_if_identical():
    d = dj.repo_signature(["a.ts", "b.ts"], None)
    e = dj.repo_signature(["a.ts", "b.ts"], None)     # identical tiny tree
    f = dj.repo_signature(["a.ts", "z.ts"], None)     # different tiny tree
    clusters = dj.cluster_signatures({"o/d": d, "o/e": e, "o/f": f})
    twos = [g for g in clusters if len(g) == 2]
    assert len(twos) == 1 and set(twos[0]) == {"o/d", "o/e"}


# --------------------------------------------------------------------------- #
# Representative selection + records
# --------------------------------------------------------------------------- #
def test_representative_is_most_substantial():
    cluster = ["o/a", "o/b"]
    metadata = {"o/a": {"stargazers_count": 5}, "o/b": {"stargazers_count": 1}}
    attribution = {"o/a": {"attributed_source_lines": 100},
                   "o/b": {"attributed_source_lines": 900}}
    assert dj.choose_representative(cluster, metadata, attribution) == "o/b"


def test_build_duplicate_records_flags_non_representatives():
    clusters = [["o/a", "o/b"], ["o/solo"]]
    metadata = {"o/a": {"stargazers_count": 9}, "o/b": {}, "o/solo": {}}
    attribution = {"o/a": {"attributed_source_lines": 500}, "o/b": {"attributed_source_lines": 10}}
    sigs = {"o/a": {"paths": frozenset("abc")}, "o/b": {"paths": frozenset("abc")},
            "o/solo": {"paths": frozenset("xy")}}
    rows = dj.build_duplicate_records(clusters, metadata, attribution, sigs)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/a"]["is_representative"] is True and by["o/a"]["is_duplicate"] is False
    assert by["o/b"]["is_duplicate"] is True and by["o/b"]["duplicate_of"] == "o/a"
    assert by["o/solo"]["cluster_size"] == 1 and by["o/solo"]["is_duplicate"] is False


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def test_detect_all_end_to_end(tmp_path):
    trees = {
        "o/a": (_files(20), None),
        "o/b": (_files(20) + ["src/x.ts"], None),
        "o/c": (_files(20, prefix="lib/g"), None),
        "o/gone": None,                    # metadata not OK
    }

    def fingerprint_fn(full, branch, url):
        return trees[full]

    candidates = [{"repository_full_name": k} for k in trees]
    metadata = {k: {"repository_full_name": k, "fetch_status": "OK", "default_branch": "main"}
                for k in ("o/a", "o/b", "o/c")}
    metadata["o/gone"] = {"repository_full_name": "o/gone", "fetch_status": "NOT_FOUND"}
    attribution = {"o/a": {"attributed_source_lines": 800},
                   "o/b": {"attributed_source_lines": 50}}
    rows, clusters = dj.detect_all(candidates, metadata, attribution,
                                   tmp_path / "fp", tmp_path / "log.jsonl",
                                   fingerprint_fn, dj.DEFAULT_JACCARD_THRESHOLD)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/b"]["is_duplicate"] is True and by["o/b"]["duplicate_of"] == "o/a"
    assert by["o/a"]["is_representative"] is True
    assert by["o/gone"]["status"] == "UNAVAILABLE"
