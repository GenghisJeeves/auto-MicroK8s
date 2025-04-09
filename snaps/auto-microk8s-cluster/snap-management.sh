#!/bin/sh

DEFAULT_LOG_LEVEL="WARNING"

log_level()
{
        level="$(snapctl get log.level)"
        if [ -z "$level" ]; then
                level="$DEFAULT_LOG_LEVEL"
                set_log_level $level
        fi
        echo "$level"
}

set_log_level()
{
        snapctl set log.level="$1"
}