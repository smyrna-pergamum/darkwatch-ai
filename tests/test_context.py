from darkweb_monitor.ai.base import AIError
from darkweb_monitor.ai.context import ContextBudget, chunk_text, estimate_tokens, is_context_overflow
from darkweb_monitor.ai.router import AIRouter
from conftest import FakeProvider, Unavailable


def test_chunk_text_respects_size_and_boundaries():
    text = "\n\n".join(f"Paragraph {i}. " + "word " * 60 for i in range(40))
    chunks = chunk_text(text, 1000, overlap=100)
    assert len(chunks) > 5 and all(len(c) <= 1000 for c in chunks)
    assert chunks[0].startswith("Paragraph 0.")
    assert chunk_text("short", 1000) == ["short"]
    assert len(chunk_text("x" * 50000, 1000, max_chunks=8)) == 8


def test_overflow_detection():
    assert is_context_overflow("the request exceeds the available context size, try increasing it")
    assert is_context_overflow("This model's maximum context length is 4096 tokens")
    assert is_context_overflow("prompt has 9,000 tokens, but the configured context size is 4,096 tokens")
    assert not is_context_overflow("rate limit: too many requests")
    assert not is_context_overflow("connection refused")


def test_budget():
    b = ContextBudget(4096, 1024, 600)
    assert b.input_tokens == 2472 and b.shrink().window == 2048
    assert estimate_tokens("a" * 320) == 101


def test_long_page_is_mapped_and_reduced_for_small_model():
    page = "\n\n".join(f"Section {i}: " + ("acme leak data " * 40) for i in range(30))  # ~18k chars

    def handler(prompt):
        if "partial analyses" in prompt:
            return {"summary": "merged summary of whole page"}
        if "Condense" in prompt:
            return {"points": ["p"]}
        sev = "critical" if "Section 29" in prompt else "low"
        return {"summary": "part", "severity": sev, "category": "leak_site",
                "iocs": [{"type": "domain", "value": "acme.com"}], "entities": ["ACME"]}
    local = FakeProvider("ollama", handler, window=2048)
    r = AIRouter(local=local, cloud=Unavailable("cloud"))
    res = r.analyze_page("u", "t", page, ["acme"])
    page_prompts = [p for p in local.prompts if "Analyse this page" in p]
    assert len(page_prompts) > 3                       # split into parts
    assert all(len(p) < 2048 * 3.2 for p in local.prompts)  # every request fits the window
    assert res["severity"] == "critical" and res["summary"] == "merged summary of whole page"
    assert res["iocs"] == [{"type": "domain", "value": "acme.com"}] and res["parts"] == len(page_prompts)


def test_overflow_error_shrinks_and_retries():
    calls = []

    def handler(prompt):
        calls.append(len(prompt))
        if len(prompt) > 4000:
            return AIError("context length exceeded", "CONTEXT_OVERFLOW")
        if "partial analyses" in prompt:
            return {"summary": "m"}
        return {"summary": "s", "severity": "medium", "category": "forum"}
    local = FakeProvider("ollama", handler, window=8192)  # claims 8k, really ~1.2k tokens
    r = AIRouter(local=local, cloud=Unavailable("cloud"))
    res = r.analyze_page("u", "t", "word " * 6000, [])
    assert res["severity"] == "medium"
    assert r.stats["overflow_retries"] >= 1 and max(calls[-3:]) <= 4000
