---
name: daily-summary
description: Creates a daily summary of completed tasks
type: skill
---

# Daily Summary Skill

When invoked, review the user's recent git commits and task completions,
then provide a concise summary in Hebrew.

## Steps
1. Run `git log --oneline -10` to see recent commits
2. Check the task list for completed items today
3. Format a brief summary with:
   - Number of commits
   - Key changes made
   - Remaining open tasks

## Output Format
Use a clean markdown list with Hebrew headers.
Keep it under 10 lines.
