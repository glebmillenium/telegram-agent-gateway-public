"""Only a fixed, deliberately fake token is used; no real credentials/network."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import getpass
import os
from pathlib import Path
import warnings
from types import SimpleNamespace

import pytest

from telegram_gateway import dpapi_store as store
from telegram_gateway import secret_input as cli

FAKE_TOKEN = "123456789:" + "A" * 35  # Fixed synthetic fixture, never a credential.


@pytest.fixture
def fake_crypto(monkeypatch):
    calls = []
    def crypt(data, *, decrypt):
        calls.append((data, decrypt))
        if decrypt:
            if data != b"opaque-test-ciphertext":
                raise ValueError(FAKE_TOKEN)
            return FAKE_TOKEN.encode("ascii")
        assert data == FAKE_TOKEN.encode("ascii")
        return b"opaque-test-ciphertext"
    monkeypatch.setattr(store, "_crypt", crypt)
    return calls


@pytest.mark.parametrize("value", [None, b"x", "", "token", "0:" + "A" * 35,
    "1:" + "A" * 34, "1:" + "A" * 36, FAKE_TOKEN + "\n", " " + FAKE_TOKEN,
    "1:" + "!" * 35, "4503599627370496:" + "A" * 35])
def test_invalid_token_rejected_without_crypto(value, fake_crypto):
    with pytest.raises(store.TokenStoreError, match="Token storage is unavailable"):
        store.protect_token(value)
    assert not fake_crypto


def test_mock_crypto_roundtrip_has_no_plaintext(fake_crypto):
    blob = store.protect_token(FAKE_TOKEN)
    assert FAKE_TOKEN.encode() not in blob
    assert store.unprotect_token(blob) == FAKE_TOKEN
    assert [decrypt for _, decrypt in fake_crypto] == [False, True]


@pytest.mark.parametrize("blob", [b"", b"plaintext", b"x" * 16385, store._MAGIC, None, "string"])
def test_bad_blob_never_decrypts(blob, fake_crypto):
    with pytest.raises(store.TokenStoreError):
        store.unprotect_token(blob)
    assert not fake_crypto


def test_corrupted_blob_generic_error(fake_crypto):
    with pytest.raises(store.TokenStoreError) as error:
        store.unprotect_token(store._MAGIC + b"corrupted")
    assert FAKE_TOKEN not in str(error.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem handle checks")
def test_exclusive_store_and_bounded_load(tmp_path, fake_crypto):
    output = tmp_path / "bot.dpapi"
    store.store_token_file(output, FAKE_TOKEN)
    ciphertext = output.read_bytes()
    assert FAKE_TOKEN.encode() not in ciphertext
    assert store.load_token(output) == FAKE_TOKEN
    with pytest.raises(store.TokenStoreError):
        store.store_token_file(output, FAKE_TOKEN)
    assert output.read_bytes() == ciphertext
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bot.dpapi"]


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem handle checks")
def test_oversized_file_rejected_before_crypto(tmp_path, fake_crypto):
    output = tmp_path / "large.dpapi"
    output.write_bytes(b"x" * 16385)
    with pytest.raises(store.TokenStoreError):
        store.load_token(output)
    assert not fake_crypto


@pytest.mark.parametrize("path", ["relative.dpapi", r"D:\file:stream", r"\\host\share\file",
    r"D:\parent\..\file", r"D:\parent\CON", r"D:\parent\name.", r"D:\parent\name "])
def test_invalid_path_before_crypto(path, fake_crypto):
    with pytest.raises(store.TokenStoreError):
        store.store_token_file(path, FAKE_TOKEN)
    assert not fake_crypto


def test_checkout_destination_rejected_before_filesystem_or_prompt(monkeypatch, capsys):
    monkeypatch.setattr(store, "_Files", lambda: pytest.fail("Must not inspect checkout target"))
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: pytest.fail("Must not prompt"))
    assert cli.main(["--output", str(store._PROJECT_ROOT / "token.dpapi")]) == 1
    assert FAKE_TOKEN not in capsys.readouterr().err


def test_filesystem_alias_to_checkout_rejected(monkeypatch, tmp_path):
    project = tmp_path / "checkout"
    alias = tmp_path / "different-drive-alias"
    monkeypatch.setattr(store, "_PROJECT_ROOT", project)
    def resolve(path, *, strict):
        assert strict is True
        return project if path in (project, alias) else path
    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(store.TokenStoreError):
        store._physical_external(alias)


@pytest.mark.parametrize("attributes, links", [(0x400, 1), (0x10, 1), (0x80, 2)])
def test_open_rejects_reparse_directory_and_hardlinked_file(attributes, links, tmp_path):
    closed = []
    def information(handle, pointer):
        info = ctypes.cast(pointer, ctypes.POINTER(store._FileInfo)).contents
        info.attributes, info.links = attributes, links
        return True
    files = object.__new__(store._Files)
    files.api = SimpleNamespace(CreateFileW=lambda *a: 123,
                                GetFileInformationByHandle=information,
                                CloseHandle=closed.append)
    with pytest.raises(store.TokenStoreError):
        files.open(tmp_path / "synthetic.dpapi")
    assert closed == [123]


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem handle checks")
def test_missing_parent_and_existing_target_before_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: pytest.fail("Must not prompt"))
    assert cli.main(["--output", str(tmp_path / "missing" / "bot.dpapi")]) == 1
    output = tmp_path / "exists.dpapi"
    output.write_bytes(b"unchanged")
    assert cli.main(["--output", str(output)]) == 1
    assert output.read_bytes() == b"unchanged"


@pytest.fixture
def fake_output(monkeypatch):
    class Output:
        values = []
        def store(self, token):
            self.values.append(token)
    result = Output()
    @contextmanager
    def prepared(path):
        yield result
    monkeypatch.setattr(cli, "prepare_token_file", prepared)
    return result


def test_cli_requires_tty_before_prompt(monkeypatch, fake_output, capsys):
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: pytest.fail("Must not prompt"))
    assert cli.main(["--output", "synthetic-path"]) == 1
    assert not fake_output.values
    assert "Token input failed" in capsys.readouterr().err


def test_cli_hidden_prompt_success_no_echo(monkeypatch, fake_output, capsys):
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: FAKE_TOKEN)
    assert cli.main(["--output", "synthetic-path"]) == 0
    assert fake_output.values == [FAKE_TOKEN]
    result = capsys.readouterr()
    assert FAKE_TOKEN not in result.out + result.err
    assert "Encrypted token saved" in result.out


def test_getpass_cannot_fallback_to_echo(monkeypatch, fake_output, capsys):
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    def warning_prompt(prompt):
        warnings.warn("Cannot hide input", getpass.GetPassWarning)
        pytest.fail("Warning must stop input before fallback read")
    monkeypatch.setattr(getpass, "getpass", warning_prompt)
    assert cli.main(["--output", "synthetic-path"]) == 1
    assert not fake_output.values
    assert "Cannot hide input" not in capsys.readouterr().err


@pytest.mark.parametrize("failure", [ValueError(FAKE_TOKEN), KeyboardInterrupt(), EOFError(FAKE_TOKEN)])
def test_prompt_errors_are_generic(monkeypatch, fake_output, capsys, failure):
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    def fail(prompt):
        raise failure
    monkeypatch.setattr(getpass, "getpass", fail)
    assert cli.main(["--output", "synthetic-path"]) == 1
    assert not fake_output.values
    result = capsys.readouterr()
    assert FAKE_TOKEN not in result.out + result.err


def test_cli_invalid_token_and_argument_errors_never_echo(monkeypatch, fake_output, capsys):
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "invalid-private-value")
    assert cli.main(["--output", "synthetic-path"]) == 1
    assert cli.main(["--token", FAKE_TOKEN]) == 1
    assert not fake_output.values
    result = capsys.readouterr()
    assert FAKE_TOKEN not in result.out + result.err
    assert "invalid-private-value" not in result.out + result.err


def test_tty_check_cannot_be_satisfied_by_isatty_alone(monkeypatch):
    class PretendTTY:
        def isatty(self):
            return True
        def fileno(self):
            raise OSError("not a real handle")
    monkeypatch.setattr(cli.sys, "stdin", PretendTTY())
    assert not cli._interactive_terminal()


@pytest.mark.skipif(os.name != "nt", reason="Real Windows CurrentUser DPAPI")
def test_real_current_user_dpapi_fixed_fake_fixture(tmp_path):
    # This is the only native crypto test. The token is fixed synthetic data;
    # the only file belongs to pytest's fresh task-4 temporary directory.
    output = tmp_path / "fake-fixture.dpapi"
    blob = store.protect_token(FAKE_TOKEN)
    assert FAKE_TOKEN.encode() not in blob
    assert store.unprotect_token(blob) == FAKE_TOKEN
    with pytest.raises(store.TokenStoreError):
        store.unprotect_token(blob[:-1] + bytes([blob[-1] ^ 1]))
    store.store_token_file(output, FAKE_TOKEN)
    assert store.load_token(output) == FAKE_TOKEN
    assert FAKE_TOKEN.encode() not in output.read_bytes()
