"""Local file scope; excluded paths retain their raw on-disk contents."""
import os

DEFAULT_SCOPE = {
    'excluded_directories': ['.git', '.svn', '.hg', 'node_modules', 'target', 'build',
        'dist', '.cache', '.gradle', '.m2', '.npm', '.yarn', '.pnpm-store',
        '.venv', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
        '.next', '.nuxt', '.turbo', '.parcel-cache', 'coverage', '.tox', '.nox',
        'CMakeFiles', 'tmp', 'temp', 'logs'],
    'included_extensions': ['.java', '.kt', '.kts', '.scala', '.groovy', '.py', '.pyi',
        '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.htm', '.css',
        '.scss', '.sass', '.less', '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hxx',
        '.cs', '.fs', '.vb', '.go', '.rs', '.php', '.rb', '.swift', '.m', '.mm',
        '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.sql', '.proto', '.graphql',
        '.xml', '.json', '.jsonc', '.yaml', '.yml', '.toml', '.ini', '.conf', '.config',
        '.cfg', '.properties', '.env', '.txt', '.md', '.rst', '.adoc', '.csv', '.tsv',
        '.svg', '.qss', '.ui', '.qrc', '.cmake', '.gradle', '.sln', '.csproj',
        '.fsproj', '.vbproj', '.props', '.targets', '.resx', '.xaml', '.ipynb',
        '.r', '.lua', '.pl', '.dart', '.ex', '.exs', '.erl', '.hrl', '.clj',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.dwg', '.dxf'],
    'included_names': ['Makefile', 'GNUmakefile', 'CMakeLists.txt', 'Dockerfile',
        'Containerfile', 'Jenkinsfile', 'Vagrantfile', 'Gemfile', 'Rakefile',
        'LICENSE', 'COPYING', 'NOTICE', 'README', '.gitignore', '.gitattributes',
        '.gitmodules', '.editorconfig', '.dockerignore', '.npmrc', '.yarnrc',
        '.prettierrc', '.eslintrc', '.babelrc', '.env', 'mvnw', 'gradlew'],
}


def normalize_scope(raw=None):
    raw = raw if isinstance(raw, dict) else {}
    result = {}
    for key, default in DEFAULT_SCOPE.items():
        values = raw.get(key, default)
        if not isinstance(values, list):
            raise ValueError(f'文件范围 {key} 必须是列表')
        result[key] = []
        for value in values:
            if not isinstance(value, str) or not value or any(c in value for c in '/,\0\n\r') or value in {'.', '..'}:
                raise ValueError(f'无效的文件范围条目：{value!r}')
            value = value.lower() if key == 'included_extensions' else value
            if key == 'included_extensions' and not value.startswith('.'):
                raise ValueError('文件扩展名必须以点开头')
            if value not in result[key]:
                result[key].append(value)
    return result


def scope_environment(scope=None, compat_modules=None):
    scope = normalize_scope(scope)
    from compat.registry import environment
    return dict(os.environ,
        **environment(compat_modules),
        YT_SCOPE_EXCLUDED_DIRS=','.join(scope['excluded_directories']),
        YT_SCOPE_EXTENSIONS=','.join(scope['included_extensions']),
        YT_SCOPE_NAMES=','.join(scope['included_names']))
