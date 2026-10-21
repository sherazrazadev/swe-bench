## Generator contamination canary (rebuilt after every evaluation)
DeepSeek generates tasks AND is a target. Alarm: DeepSeek's solve rate on its OWN designs (self-break protocol) exceeds its solve rate on other generators' tasks by >= 20% (needs >= 5 tasks). Uses DeepSeek alone because early stop cancels MiMo once DeepSeek solves; the paired columns are context only.

| Generator | Tasks (DeepSeek measured) | DeepSeek solved | Paired tasks | Paired: DeepSeek / MiMo solved |
|---|---|---|---|---|
| claude | 33 | 85% | 9 | 44% / 44% |
| deepseek | 5 | 100% | 3 | 100% / 100% |
| handoff | 2 | 50% | 2 | 50% / 50% |

Baseline (DeepSeek on other generators' tasks): 83%. Own protocol tasks: 0, DeepSeek solved 0%.
Status: no alert (too few protocol tasks yet: 0 of 5).

Pre-protocol reference: DeepSeek-designed tasks before 2026-10-21 (old prompt) - 0 of 15 accepted.
