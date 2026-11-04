"""Ordinary Python combines observations; Host rechecks its own idle_roles."""


def choose(messages, packets):
    if not packets:
        return []
    return sorted(messages, key=lambda item: item['record']['sequence'])[:1]


def run(t):
    t.listen('new-information', kind='board.message', connection='board-b', issue_id='A')
    t.listen('new-material', kind='inbox.packet', connection='im-b', issue_id='A')
    for scans in t.poll(every=5):
        print(scans, flush=True)
        status = t.host_status('host-c')
        if all(status['by_role'][role] == 0 for role in ('experimenter', 'scientist')):
            for message in choose(list(t.pending('new-information')), list(t.pending('new-material'))):
                print(t.activate(message, host='host-c', role_profile='manager',
                                 conditions={'idle_roles': ['experimenter', 'scientist']}), flush=True)
