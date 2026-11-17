"""CSV validation and three transparent, time-window detection rules."""
import csv
import io
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta

FIELDS = ['timestamp', 'user', 'ip', 'status']

def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
    if not reader.fieldnames or not set(FIELDS).issubset(reader.fieldnames):
        raise ValueError('Required CSV columns: ' + ', '.join(FIELDS))
    events = []
    for line, row in enumerate(reader, 2):
        if len(events) >= 20000:
            raise ValueError('Maximum 20,000 events per file.')
        try:
            if None in row:
                raise ValueError('extra CSV values')
            data = {key: (row[key] or '').strip() for key in FIELDS}
            timestamp = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
            ip = str(ipaddress.ip_address(data['ip']))
            if not data['user'] or len(data['user']) > 120:
                raise ValueError('user must contain 1–120 characters')
            if data['status'] not in ('failed', 'success'):
                raise ValueError('status must be failed or success')
            events.append(dict(timestamp=timestamp, user=data['user'], ip=ip,
                               status=data['status'], row=line))
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f'CSV row {line}: {exc}') from None
    if not events:
        raise ValueError('The CSV contains no events.')
    # Stable sorting retains file order for equal timestamps.
    return sorted(events, key=lambda event: event['timestamp'])

def analyze(text, threshold=3, minutes=5):
    if type(threshold) is not int or not 2 <= threshold <= 20:
        raise ValueError('Threshold must be an integer between 2 and 20.')
    if type(minutes) is not int or not 1 <= minutes <= 60:
        raise ValueError('Window must be an integer between 1 and 60 minutes.')
    events = parse_csv(text)
    window = timedelta(minutes=minutes)
    by_ip, by_account = defaultdict(deque), defaultdict(deque)
    active = defaultdict(set)
    alerts = []
    actions = {
        'BURST': 'Check the source, targeted accounts and expected user activity. Consider rate limits and MFA.',
        'SUCCESS_AFTER_FAILURES': 'Verify the login with the account owner. Review session activity and revoke suspicious sessions if confirmed.',
        'MULTI_ACCOUNT': 'Review whether the source is a shared gateway or an authorized service before blocking it.'
    }
    def emit(rule, event, evidence):
        alerts.append(dict(id=f'ALT-{len(alerts)+1:03}', rule=rule,
            severity='High' if rule == 'SUCCESS_AFTER_FAILURES' else 'Medium',
            timestamp=str(event['timestamp']), ip=event['ip'], user=event['user'],
            count=len(evidence), users=sorted({e['user'] for e in evidence}),
            evidence=[dict(row=e['row'], timestamp=str(e['timestamp']), user=e['user'], status=e['status']) for e in evidence],
            action=actions[rule]))
    for event in events:
        now, ip = event['timestamp'], event['ip']
        account = (ip, event['user'])
        recent = by_ip[ip]
        personal = by_account[account]
        for queue in (recent, personal):
            while queue and now - queue[0]['timestamp'] > window:
                queue.popleft()
        # Re-arm a rule once its count falls below the threshold.
        if len(recent) < threshold:
            active[ip].discard('BURST')
        if len({e['user'] for e in recent}) < threshold:
            active[ip].discard('MULTI_ACCOUNT')
        if event['status'] == 'failed':
            recent.append(event)
            personal.append(event)
            if len(recent) >= threshold and 'BURST' not in active[ip]:
                emit('BURST', event, list(recent))
                active[ip].add('BURST')
            if len({e['user'] for e in recent}) >= threshold and 'MULTI_ACCOUNT' not in active[ip]:
                emit('MULTI_ACCOUNT', event, list(recent))
                active[ip].add('MULTI_ACCOUNT')
        else:
            if len(personal) >= threshold:
                emit('SUCCESS_AFTER_FAILURES', event, list(personal) + [event])
            personal.clear()
    return dict(summary=dict(events=len(events), failures=sum(e['status']=='failed' for e in events),
        ips=len({e['ip'] for e in events}), alerts=len(alerts)), alerts=alerts,
        events=[{**e, 'timestamp':str(e['timestamp'])} for e in events],
        settings=dict(threshold=threshold, minutes=minutes))
