#!/usr/bin/env bash
# Detached launcher for fix_and_retest_stage3.sh.
# Invoked from PowerShell as:
#   vagrant ssh vm-ot -c 'sudo bash /vagrant/infra/tests/launch_stage3.sh'
# Returns immediately. Output is written to /tmp/stage3.log; the script
# is guaranteed to terminate within ~60s thanks to in-script watchdogs.
set +e
pkill -9 -f stage3              >/dev/null 2>&1 || true
pkill -9 -f fix_and_retest      >/dev/null 2>&1 || true
rm -f /tmp/stage3.run /tmp/stage3.log
nohup bash /vagrant/infra/tests/fix_and_retest_stage3.sh \
    >/tmp/stage3.run 2>&1 </dev/null &
disown
echo "stage3 runner launched, pid=$!"
