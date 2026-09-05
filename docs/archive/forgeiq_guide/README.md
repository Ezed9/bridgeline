# Archived: the forgeiq guide (superseded)

These phase docs describe an earlier, abandoned design: an MCP **stdio proxy**
in front of a LangGraph agent with a ChromaDB RAG layer.

They are kept for reference only. `crawlgate` deliberately does not build that:

- It uses the **bouncer library core** (`ContractEngine`), not the stdio proxy.
- It has **no LangGraph**. A graph executor that re-feeds tool output to the
  model is precisely the vulnerability this project exists to close.
- It has **no vector store**. Crawled pages are untrusted data, not context.

The authoritative design is `/SPEC.md`.
