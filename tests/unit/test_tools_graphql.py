"""Unit tests for GraphQL security checker constants."""

from __future__ import annotations

from tengu.tools.api.graphql import (
    _BATCH_QUERIES,
    _DEPTH_QUERY,
    _INTROSPECTION_QUERY,
    _SUGGESTION_QUERY,
)

# ---------------------------------------------------------------------------
# TestDepthQuery
# ---------------------------------------------------------------------------


class TestDepthQuery:
    def test_is_string(self):
        assert isinstance(_DEPTH_QUERY, str)

    def test_non_empty(self):
        assert len(_DEPTH_QUERY.strip()) > 0

    def test_deeply_nested(self):
        # Query should have many levels of nesting (at least 5 levels deep)
        assert _DEPTH_QUERY.count("{") >= 5

    def test_contains_typename(self):
        assert "__typename" in _DEPTH_QUERY

    def test_valid_graphql_braces_balanced(self):
        stripped = _DEPTH_QUERY.replace("\n", "").replace(" ", "")
        assert stripped.count("{") == stripped.count("}")


# ---------------------------------------------------------------------------
# TestSuggestionQuery
# ---------------------------------------------------------------------------


class TestSuggestionQuery:
    def test_is_string(self):
        assert isinstance(_SUGGESTION_QUERY, str)

    def test_non_empty(self):
        assert len(_SUGGESTION_QUERY.strip()) > 0

    def test_contains_typo_field(self):
        # Typo in field name to trigger suggestion leak
        assert "__typ" in _SUGGESTION_QUERY


# ---------------------------------------------------------------------------
# TestIntrospectionQuery
# ---------------------------------------------------------------------------


class TestIntrospectionQuery:
    def test_is_string(self):
        assert isinstance(_INTROSPECTION_QUERY, str)

    def test_contains_schema(self):
        assert "__schema" in _INTROSPECTION_QUERY

    def test_contains_types(self):
        assert "types" in _INTROSPECTION_QUERY

    def test_contains_name(self):
        assert "name" in _INTROSPECTION_QUERY


# ---------------------------------------------------------------------------
# TestBatchQueries
# ---------------------------------------------------------------------------


class TestBatchQueries:
    def test_is_list(self):
        assert isinstance(_BATCH_QUERIES, list)

    def test_has_at_least_two_items(self):
        assert len(_BATCH_QUERIES) >= 2

    def test_each_item_has_query_key(self):
        for item in _BATCH_QUERIES:
            assert "query" in item

    def test_each_query_is_string(self):
        for item in _BATCH_QUERIES:
            assert isinstance(item["query"], str)

    def test_first_query_is_introspection(self):
        assert "__schema" in _BATCH_QUERIES[0]["query"]

    def test_second_query_uses_typename(self):
        assert "__typename" in _BATCH_QUERIES[1]["query"]
