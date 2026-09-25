# Upgrade notes used by scripts/check-migrations_test.sh

Migration 90050 rewrites a column type; the fixture says why.
Migration 900511 has a longer number, which must not count as naming the marked fixture that is five digits long.
Migration 90052 is described here but carries no marker, so it is still refused.
Migration 90053 drops a unique constraint; the fixture says why.
