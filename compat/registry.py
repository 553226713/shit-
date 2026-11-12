"""Compatibility selections; no cipher or file-state logic belongs here."""
MODULES = {
    'git': {'raw_clients': ['git', 'git-*'], 'script_clients': []},
    'svn': {'raw_clients': ['svn', 'svnadmin', 'svnlook', 'svnrdump', 'svnmucc', 'svnsync'], 'script_clients': []},
    'hg': {'raw_clients': ['hg'], 'script_clients': ['hg', 'hg.py']},
}


def environment(enabled=None):
    enabled = list(MODULES) if enabled is None else enabled
    raw, scripts = [], []
    for name in enabled:
        module = MODULES[name]
        raw.extend(module['raw_clients'])
        scripts.extend(module['script_clients'])
    return {'YT_COMPAT_RAW_CLIENTS': ','.join(raw), 'YT_COMPAT_SCRIPT_CLIENTS': ','.join(scripts)}
