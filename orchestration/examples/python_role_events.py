"""Optional project policy: explicit work and requests, not a fixed role chain.

Configure all named connections and profile permissions in the trusted Host.
This example watches one actual Issue; it does not infer project completion or
invent an event when the Queue is quiet.
"""


def run(t):
    t.listen('role-work', kind='queue.task', connection='queue-work', issue_id='A')
    t.listen('material', kind='inbox.packet', connection='im-reader', issue_id='A', initial='new_only')
    t.listen('manager-request', kind='board.handoff', connection='board-manager', issue_id='A', initial='new_only')
    t.listen('scientist-request', kind='board.handoff', connection='board-scientist', issue_id='A', initial='new_only')
    for scans in t.poll(every=5):
        if any(scan.get('error') or scan.get('isError') for scan in scans):
            raise RuntimeError('Source scan failed; preserve the original candidates and inspect diagnostics')
        for task in t.pending('role-work'):
            print(t.activate(task, host='host'), flush=True)
        # The project has explicitly chosen new material as a curation opportunity.
        for packet in t.pending('material'):
            print(t.activate(packet, host='host', role_profile='curator'), flush=True)
        for watch, role in [('manager-request', 'manager'), ('scientist-request', 'scientist')]:
            for request in t.pending(watch):
                print(t.activate(request, host='host', role_profile=role), flush=True)
