import win32evtlog
import win32evtlogutil
import win32con

# Event IDs worth surfacing, with plain-language explanations
INTERESTING_EVENTS = {
    4624: "Successful login",
    4625: "Failed login attempt",
    4720: "A new user account was created",
    4732: "A user was added to an administrator group",
    4697: "A new service was installed",
    1102: "The security audit log was cleared",
}

def get_security_events(max_events=50):
    events = []
    server = 'localhost'
    log_type = 'Security'
    
    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        return {'error': f"Could not open Security event log: {e}. This usually requires running as Administrator."}
    
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    count = 0
    
    while count < max_events:
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        if not records:
            break
        
        for record in records:
            event_id = record.EventID & 0xFFFF  # Windows encodes extra data in upper bits, mask it off
            if event_id in INTERESTING_EVENTS:
                events.append({
                    'event_id': event_id,
                    'description': INTERESTING_EVENTS[event_id],
                    'time': str(record.TimeGenerated),
                    'source': record.SourceName
                })
                count += 1
                if count >= max_events:
                    break
    
    win32evtlog.CloseEventLog(handle)
    return events

if __name__ == '__main__':
    result = get_security_events()
    if isinstance(result, dict) and 'error' in result:
        print(result['error'])
    else:
        print(f"Found {len(result)} relevant security events")
        for e in result[:20]:
            print(e)