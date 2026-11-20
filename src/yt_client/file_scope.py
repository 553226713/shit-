"""Directory and extension filters for file monitoring."""
import os
from pathlib import Path
import re

DEFAULT_SCOPE = {
    'excluded_directories': [],
    'included_extensions': [],
    'included_names': [],
}

DEFAULT_EXCLUDED_DIRECTORY_NAMES = (
    '.angular', '.cache', '.dart_tool', '.git', '.gradle', '.hg', '.mypy_cache',
    '.next', '.nox', '.nuxt', '.output', '.parcel-cache', '.pytest_cache',
    '.ruff_cache', '.svelte-kit', '.svn', '.tox', '.turbo', '.venv', '.vite',
    'CMakeFiles', '__pycache__', 'bower_components', 'build',
    'cmake-build-debug', 'cmake-build-release', 'coverage', 'dist',
    'node_modules', 'obj', 'out', 'target', 'temp', 'tmp', 'venv',
)
DEFAULT_MONITORED_EXTENSIONS = (
    '.bash', '.c', '.cc', '.cpp', '.cs', '.css', '.cxx', '.dart', '.erl',
    '.ex', '.exs', '.fs', '.fsx', '.go', '.gradle', '.groovy', '.h', '.hh',
    '.hpp', '.hrl', '.htm', '.html', '.hxx', '.java', '.js', '.jsx', '.kt',
    '.kts', '.less', '.lua', '.m', '.mm', '.php', '.ps1', '.py', '.pyi',
    '.r', '.rb', '.rs', '.sass', '.scala', '.scss', '.sh', '.sql', '.svelte',
    '.swift', '.ts', '.tsx', '.vb', '.vue', '.zsh',
)


def normalize_scope(raw=None):
    # Stored restrictions from older versions no longer exclude monitored files.
    return {key: list(value) for key, value in DEFAULT_SCOPE.items()}


def normalize_excluded_directories(raw):
    if not isinstance(raw, list):
        return []
    paths = set()
    for path in raw:
        if isinstance(path, str) and path.startswith('/') and '\0' not in path and '\n' not in path:
            normalized = os.path.normpath('/' + path.lstrip('/'))
            if normalized != '/':
                paths.add(normalized)
    return sorted(paths)


def normalize_monitored_extensions(raw):
    if isinstance(raw, str):
        raw = re.split(r'[,，\s]+', raw.strip()) if raw.strip() else []
    if not isinstance(raw, list):
        raise ValueError('监控文件类型必须是扩展名列表。')
    extensions = set()
    for item in raw:
        if isinstance(item, str) and not item:
            continue
        if not isinstance(item, str) or not re.fullmatch(r'\.?[a-zA-Z0-9_+-]+(?:\.[a-zA-Z0-9_+-]+)*', item):
            raise ValueError('请输入有效扩展名，例如 .java、.py 或 .d.ts。')
        extensions.add('.' + item.lstrip('.').lower())
    return sorted(extensions)


def excludes_directory(directory, root, excluded_directories, use_default_directory_exclusions):
    if any(directory.is_relative_to(path) for path in excluded_directories):
        return True
    return use_default_directory_exclusions and any(
        part in DEFAULT_EXCLUDED_DIRECTORY_NAMES for part in directory.relative_to(root).parts)


def scope_environment(excluded_directories=None, root=Path('/'), monitored_extensions=(),
                      *, use_default_directory_exclusions=True):
    environment = dict(os.environ)
    for key in ('YT_COMPAT_RAW_CLIENTS', 'YT_COMPAT_SCRIPT_CLIENTS'):
        environment.pop(key, None)
    # The engine sees paths relative to the mount root.
    exclusions = []
    for path in normalize_excluded_directories(excluded_directories):
        directory = Path(path)
        if root.is_relative_to(directory):
            exclusions = ['/']
            break
        if root in directory.parents:
            exclusions.append('/' + str(directory.relative_to(root)))
    return dict(environment,
        YT_SCOPE_EXCLUDED_DIRS='',
        YT_SCOPE_EXTENSIONS='',
        YT_SCOPE_NAMES='',
        YT_EXCLUDED_DIRS='\n'.join(exclusions),
        YT_EXCLUDED_DIR_NAMES='\n'.join(DEFAULT_EXCLUDED_DIRECTORY_NAMES)
        if use_default_directory_exclusions else '',
        YT_MONITORED_EXTENSIONS='\n'.join(monitored_extensions))
