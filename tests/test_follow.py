import os

from logsentinel.follow import Tailer


def test_reads_only_new_lines_by_default(tmp_path):
    path = tmp_path / "log"
    path.write_text("старая строка\n")
    t = Tailer(path)
    assert t.read_new() == []
    with open(path, "a") as fh:
        fh.write("новая 1\nновая 2\n")
    assert t.read_new() == ["новая 1", "новая 2"]
    assert t.read_new() == []
    t.close()


def test_from_start_reads_everything(tmp_path):
    path = tmp_path / "log"
    path.write_text("a\nb\n")
    t = Tailer(path, from_start=True)
    assert t.read_new() == ["a", "b"]
    t.close()


def test_partial_line_waits_for_newline(tmp_path):
    path = tmp_path / "log"
    path.write_text("")
    t = Tailer(path)
    t.read_new()
    with open(path, "a") as fh:
        fh.write("целая\nполови")
    assert t.read_new() == ["целая"]
    with open(path, "a") as fh:
        fh.write("на\n")
    assert t.read_new() == ["половина"]
    t.close()


def test_rotation_new_file_is_read_from_start(tmp_path):
    path = tmp_path / "log"
    path.write_text("до ротации\n")
    t = Tailer(path)
    t.read_new()
    os.rename(path, tmp_path / "log.1")
    path.write_text("после 1\nпосле 2\n")
    assert t.read_new() == ["после 1", "после 2"]
    t.close()


def test_truncated_file_is_read_again(tmp_path):
    path = tmp_path / "log"
    path.write_text("x" * 100 + "\n")
    t = Tailer(path, from_start=True)
    t.read_new()
    path.write_text("коротко\n")
    assert t.read_new() == ["коротко"]
    t.close()


def test_missing_file_is_not_an_error(tmp_path):
    assert Tailer(tmp_path / "нет").read_new() == []
