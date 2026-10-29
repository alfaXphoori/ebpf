# Week 26: shrink one Tetragon JSON event to the fields we care about.
# Usage: ./run-tetragon.sh capture-json 10 --policy-names w26-file-monitor | jq -c -f event-summary.jq
# Note: Tetragon's JSON (protobuf) omits zero values, so "status": 0 is simply absent.
to_entries[0]
| .key as $type
| .value as $e
| {
    type:   $type,
    policy: ($e.policy_name // null),
    hook:   ($e.function_name // null),
    binary: $e.process.binary,
    pid:    $e.process.pid,
    argv:   ($e.process.arguments // null),
    args:   ( [ $e.args[]? |
                ( .file_arg.path
                // .linux_binprm_arg.path
                // ( if .sock_arg then "\(.sock_arg.saddr):\(.sock_arg.sport) -> \(.sock_arg.daddr):\(.sock_arg.dport)" else null end )
                // . ) ]
              | if length == 0 then null else . end ),
    return: ($e.return.int_arg // null),
    action: ($e.action // null),
    exit_status: ( if $type == "process_exit" then ($e.status // 0) else null end ),
    signal: ($e.signal // null)
  }
| with_entries(select(.value != null))
