from datetime import datetime, timedelta, timezone

import pytest

from logsentinel.models import Event

T0 = datetime(2026, 11, 4, 9, 0, 0, tzinfo=timezone.utc)


def http(seconds, ip="203.0.113.5", method="GET", path="/", status=200, ua="Mozilla/5.0"):
    return Event(ts=T0 + timedelta(seconds=seconds), source="nginx", kind="http", ip=ip,
                 method=method, path=path, status=status, user_agent=ua)


def ssh(seconds, kind, user="root", ip="203.0.113.5"):
    return Event(ts=T0 + timedelta(seconds=seconds), source="sshd", kind=kind, ip=ip, user=user)


@pytest.fixture
def make_http():
    return http


@pytest.fixture
def make_ssh():
    return ssh
