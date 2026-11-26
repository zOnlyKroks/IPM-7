from app.nvd_mirror import resume_point


def test_resumes_only_an_unfinished_mirror():
    assert resume_point(None) == (0, None)
    assert resume_point({"mirror_index": 4000, "mirror_started": "t"}) == (4000, "t")
    assert resume_point({"mirror": True, "last_modified": "t"}) == (0, None)
