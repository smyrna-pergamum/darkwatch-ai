"""Learning from analyst feedback - without retraining the model.

* feedback.py  - explicit (agree / disagree / correct verdict) and implicit
                 (alert status changes) labels; only humans create labels
* lessons.py   - human-confirmed lessons retrieved into future investigations
* rules.py     - per-watch-term quality stats and context suppression rules
* evalcases.py - corrected cases frozen as regression tests for the analyst

Safety: the system never learns from page content or from its own output.
AI-drafted lessons and statistically proposed rules stay "proposed" until a
human approves them.
"""
