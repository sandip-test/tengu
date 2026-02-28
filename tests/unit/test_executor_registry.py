"""Unit tests for tool executor registry."""

from __future__ import annotations

import pytest

from tengu.exceptions import ToolNotFoundError
from tengu.executor.registry import _TOOL_CATALOG, check_tool, resolve_tool_path

# ---------------------------------------------------------------------------
# TestToolCatalog
# ---------------------------------------------------------------------------


class TestToolCatalog:
    def test_is_list(self):
        assert isinstance(_TOOL_CATALOG, list)

    def test_has_many_tools(self):
        assert len(_TOOL_CATALOG) >= 20

    def test_each_entry_has_name(self):
        for entry in _TOOL_CATALOG:
            assert "name" in entry
            assert isinstance(entry["name"], str)

    def test_each_entry_has_category(self):
        for entry in _TOOL_CATALOG:
            assert "category" in entry
            assert isinstance(entry["category"], str)

    def test_nmap_present(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "nmap" in names

    def test_nuclei_present(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "nuclei" in names

    def test_sqlmap_present(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "sqlmap" in names

    def test_categories_include_recon(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "recon" in categories

    def test_categories_include_web(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "web" in categories

    def test_categories_include_exploit(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "exploit" in categories

    def test_no_duplicate_names(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# TestCheckTool
# ---------------------------------------------------------------------------


class TestCheckTool:
    def test_python3_found(self):
        result = check_tool("python3")
        assert result.name == "python3"
        assert result.available is True
        assert result.path is not None

    def test_nonexistent_tool_not_available(self):
        result = check_tool("this_tool_does_not_exist_xyz")
        assert result.available is False
        assert result.path is None

    def test_category_preserved(self):
        result = check_tool("python3", category="utility")
        assert result.category == "utility"

    def test_returns_tool_status(self):
        from tengu.types import ToolStatus
        result = check_tool("python3")
        assert isinstance(result, ToolStatus)

    def test_name_preserved_in_result(self):
        result = check_tool("python3")
        assert result.name == "python3"


# ---------------------------------------------------------------------------
# TestResolveToolPath
# ---------------------------------------------------------------------------


class TestResolveToolPath:
    def test_configured_path_takes_priority(self):
        result = resolve_tool_path("nmap", configured_path="/usr/custom/nmap")
        assert result == "/usr/custom/nmap"

    def test_python3_resolved_from_path(self):
        result = resolve_tool_path("python3")
        assert "python3" in result

    def test_missing_tool_raises_tool_not_found(self):
        with pytest.raises(ToolNotFoundError):
            resolve_tool_path("tool_that_definitely_does_not_exist_abc123")

    def test_tool_not_found_includes_tool_name(self):
        try:
            resolve_tool_path("phantom_tool_xyz")
        except ToolNotFoundError as exc:
            assert "phantom_tool_xyz" in str(exc)
