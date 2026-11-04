"""Trusted user script; configure these connection/profile names in your Host."""


def run(t):
    t.listen('queue-work', kind='queue.task', connection='queue-b', issue_id='A')
    t.listen('new-material', kind='inbox.packet', connection='im-b', issue_id='A', initial='new_only')
    for scans in t.poll(every=5):
        print(scans, flush=True)
        for task in t.pending('queue-work'):
            print(t.activate(task, host='host-c'), flush=True)
        for packet in t.pending('new-material'):
            print(t.activate(packet, host='host-c', role_profile='curator'), flush=True)
