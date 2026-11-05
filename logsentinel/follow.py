"""Чтение файла по мере появления новых строк (как tail -f), с учётом ротации логов."""
from __future__ import annotations

import os
from pathlib import Path


class Tailer:
    def __init__(self, path: str | Path, from_start: bool = False):
        self.path = Path(path)
        self.from_start = from_start
        self._fh = None
        self._inode: int | None = None
        self._opened_before = False

    def _open(self, seek_end: bool) -> None:
        self._fh = open(self.path, "rb")
        self._inode = os.fstat(self._fh.fileno()).st_ino
        if seek_end:
            self._fh.seek(0, os.SEEK_END)
        self._opened_before = True

    def read_new(self) -> list[str]:
        """Возвращает только полные строки. Недописанная строка остаётся до следующего вызова."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        if self._fh is None:
            # При первом открытии по умолчанию идём в конец, после ротации читаем новый файл сначала.
            self._open(seek_end=not self.from_start and not self._opened_before)
        elif st.st_ino != self._inode or st.st_size < self._fh.tell():
            self._fh.close()
            self._open(seek_end=False)
        data = self._fh.read()
        if not data:
            return []
        if not data.endswith(b"\n"):
            partial = data.rsplit(b"\n", 1)[-1]
            self._fh.seek(-len(partial), os.SEEK_CUR)
            data = data[: len(data) - len(partial)]
        return [line.decode("utf-8", errors="replace") for line in data.split(b"\n") if line]

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
