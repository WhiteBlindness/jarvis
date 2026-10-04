#!/usr/bin/env bash
# The README's quick start, as a script that fails on any unexpected result.
# Runs the Core with config/jarvis.example.toml, uses it through the CLI,
# approves one write and shuts it down. Needs a built `jarvis-core` and
# python3. Used by CI; safe to run locally (state goes to var/).
set -euo pipefail

cd "$(dirname "$0")/.."
config=config/jarvis.example.toml
core=${JARVIS_CORE:-target/debug/jarvis-core}
jarvis() { "$core" "$@" --config "$config"; }
field() { python3 -c "import json, sys; print(json.loads(sys.stdin.readline())['$1'])"; }

rm -rf var && mkdir -p var
"$core" serve --config "$config" > var/serve.out 2> var/serve.log &
core_pid=$!
trap 'kill "$core_pid" 2> /dev/null || true' EXIT

for _ in $(seq 1 100); do
    grep -q '^ready ' var/serve.out 2> /dev/null && break
    sleep 0.2
done
grep '^ready ' var/serve.out || { cat var/serve.log; exit 1; }

jarvis health

echo "== a class A job runs without asking"
jarvis submit "describe the runtime, then read welcome.txt" --wait

echo "== a class B write waits for a person"
job=$(jarvis submit "write notes.txt: remember the milk" --json | field job_id)
approval=$(jarvis approvals list --wait 30s --json | field approval_id)
jarvis approvals show "$approval"
test ! -e var/workspace/notes.txt
jarvis approvals approve "$approval" --yes
jarvis job "$job" --wait
test "$(cat var/workspace/notes.txt)" = "remember the milk"

echo "== a declined write changes nothing"
job=$(jarvis submit "write notes.txt: overwritten" --json | field job_id)
approval=$(jarvis approvals list --wait 30s --json | field approval_id)
jarvis approvals deny "$approval" --reason "keep the first version"
status=0
jarvis job "$job" --wait || status=$?
test "$status" -eq 2
test "$(cat var/workspace/notes.txt)" = "remember the milk"

jarvis shutdown
wait "$core_pid"
trap - EXIT

jarvis tasks
jarvis audit | tail -n 12
