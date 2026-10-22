// LLM-based ranking of search results
/* AI-powered re-ranking: scores each chunk against the query. */

export interface Chunk {
  id: string;
  text: string;
  score: number;
}

// Agent-config files are loaded once and cached.
const SYSTEM_PROMPT = "Rank the chunks by relevance to the question.";

export function topK(chunks: Chunk[], k = 10): Chunk[] {
  // Sort a copy so the caller's array is not modified.
  return [...chunks].sort((a, b) => b.score - a.score).slice(0, k);
}

export function systemPrompt(): string {
  return SYSTEM_PROMPT;
}
