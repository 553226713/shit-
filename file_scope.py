"""All files beneath configured monitor roots participate in signature checks."""
import os

DEFAULT_SCOPE = {
    'excluded_directories': [],
    'included_extensions': [],
    'included_names': [],
}


def normalize_scope(raw=None):
    # Stored restrictions from older versions no longer exclude monitored files.
    return {key: list(value) for key, value in DEFAULT_SCOPE.items()}


def scope_environment(scope=None, compat_modules=None):
    from compat.registry import environment
    return dict(os.environ,
        **environment(compat_modules),
        YT_SCOPE_EXCLUDED_DIRS='',
        YT_SCOPE_EXTENSIONS='',
        YT_SCOPE_NAMES='')
