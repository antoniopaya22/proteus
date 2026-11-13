import importlib

import pytest

from proteus.cli import COMMANDS, main


def test_help_lists_every_command(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert all(name in out for name in COMMANDS)


def test_version(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.startswith("proteus ")


def test_unknown_command(capsys):
    assert main(["fly"]) == 2
    assert "unknown command" in capsys.readouterr().err


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_every_command_has_a_main(name):
    module = importlib.import_module(COMMANDS[name][0])
    assert callable(getattr(module, "main", None))


def test_subcommand_help_reaches_the_module(capsys):
    with pytest.raises(SystemExit) as e:
        main(["frontier", "--help"])
    assert e.value.code == 0
    assert "--rmax" in capsys.readouterr().out
