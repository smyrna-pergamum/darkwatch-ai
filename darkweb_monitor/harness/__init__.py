"""A small agent harness, modelled on the ideas of DeepSeek Harness (dsh):

* an append-only **session event log** is the single source of truth -
  "model-visible means logged"; model history is *derived* from it;
* a **turn** is zero or more **steps**; a step is one model request plus the
  tool calls it makes;
* tools live in a **registry** and run through a guarded **execution
  pipeline** (argument validation -> ``tools/pre-execute`` policy ->
  approval -> ``tools/execute`` (timeout) -> ``tools/post-execute`` ->
  normalised result);
* **hooks** (waterfalls / serial events) are the extension points
  (``agent/pre-step``, ``tools/*``, ``agent/turn-stopping``);
* failures carry a **stable error code** across seams;
* the model adapter is a **seam** (Ollama / OpenAI / Anthropic / JSON
  protocol / scripted / rules).
"""
