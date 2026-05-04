# Contributing to agent-shield

Thank you for helping make AI agents safer.

## Getting Started

```bash
git clone https://github.com/cyberranger93/agent-shield
cd agent-shield
npm install
npm run build
npm test
```

## What We Need

- **New attack patterns** — add to `src/attacks/prompt-injection/basic-injections.ts`
- **Better detection logic** — improve confidence scoring in `src/scanners/`
- **New adapters** — support more LLM providers in `src/adapters/`
- **Real-world injection examples** — found in the wild (sanitized)
- **Tests** — more coverage is always welcome

## Submitting a Pull Request

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Make your changes
3. Run `npm test` — all tests must pass
4. Run `npx tsc --noEmit` — no TypeScript errors
5. Open a PR with a clear description of what you changed and why

## Adding a New Attack Pattern

```typescript
{
  id: 'PI-021',                    // Next sequential ID
  name: 'Your Attack Name',
  category: 'direct',             // direct | indirect | extraction | jailbreak | roleplay | encoding | authority | tool-poisoning
  severity: 'high',               // critical | high | medium | low
  payload: 'The actual attack string',
  description: 'What this attack does and why it works',
  detection_hints: ['keyword1', 'phrase to detect'],
}
```

## Code Style

- TypeScript strict mode — no `any` types
- Functional where possible — avoid mutation
- Every exported function must be used in at least one test

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Built by [CyberArc](https://cyberarc.co)
