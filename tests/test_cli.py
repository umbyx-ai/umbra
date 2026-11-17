from umbra.case import Case, case_slug
from umbra.menu import OPTIONS, SECTIONS
from umbra.modules import discover


def test_case_slug_blocks_path_traversal():
    assert case_slug("../../etc/passwd") == "etc_passwd"
    assert case_slug("..") == "caso"
    assert case_slug("Example.com") == "example.com"


def test_case_log_and_safe_files(tmp_path):
    case = Case("Mi Caso", tmp_path)
    assert case.dir == tmp_path / "mi_caso"
    case.log("Herramienta", "objetivo", "cuerpo")
    assert case.entries() == 1
    assert "cuerpo" in case.log_path.read_text(encoding="utf-8")
    assert case.file("../../fuera.txt").parent == case.dir
    assert Case.existing(tmp_path) == ["mi_caso"]


def test_all_modules_are_discovered():
    assert {"dns", "crtsh", "rdap", "ripestat", "internetdb", "wayback", "pivot"} <= set(discover())


def test_menu_keys_are_unique_and_callable():
    keys = [opt.key for _, options in SECTIONS for opt in options]
    assert len(keys) == len(set(keys)) == len(OPTIONS) == 18
    assert all(callable(opt.action) for opt in OPTIONS.values())
