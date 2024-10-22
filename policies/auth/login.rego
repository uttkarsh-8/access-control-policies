package auth.login

default allow = false

# Main login decision
allow = response {
    # Check required inputs
    input.username
    input.ip_address
    input.active_sessions
    
    # All checks pass
    not too_many_sessions
    not suspicious_ip
    
    response := {
        "allow": true,
        "session_id": generate_session_id
    }
}

# Too many sessions check
too_many_sessions {
    input.active_sessions >= 3
}

# IP anomaly check
suspicious_ip {
    # Check if this IP is different from user's usual IPs
    not input.usual_ips[input.ip_address]
}

generate_session_id := session_id {
    session_id := concat("-", [input.username, time.now_ns()])
}

# Response when too many sessions
allow = response {
    too_many_sessions
    response := {
        "allow": false,
        "reason": "Maximum 3 concurrent sessions allowed"
    }
}

# Response for suspicious IP
allow = response {
    suspicious_ip
    response := {
        "allow": false,
        "reason": "Login attempt from new IP detected"
    }
}