# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-28T03:59:26.792525+00:00`
- Framework: `google-adk`
- Technical failure: **True**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **False**
- Error: `jsonschema not installed`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/5`
- Attack queries blocked: `7/7`
- Edge cases blocked: `2/3`
- Rate limit blocked/sent: `2/12`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.1-flash-lite`
- Unsafe leaks (Red): `1/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `1`
- Technical failure: `False`

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
