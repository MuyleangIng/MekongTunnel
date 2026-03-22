"""
Detect the port a server command will listen on.
No external dependencies — stdlib only.
"""

FRAMEWORK_PORTS = {
    'uvicorn':   8000,
    'gunicorn':  8000,
    'hypercorn': 8000,
    'granian':   8000,
    'daphne':    8000,
    'flask':     5000,
    'manage.py': 8000,
    'fastapi':   8000,
    'tornado':   8888,
}


def detect_port(args: list) -> 'int | None':
    """
    Scan args for an explicit port, then fall back to framework defaults.

    Recognised patterns:
      --port N
      -p N
      --bind HOST:N  (gunicorn / hypercorn style)
      bare 4-5 digit integer anywhere in args
      trailing HOST:PORT token  (e.g. manage.py runserver 0.0.0.0:8000)

    Returns an int or None.
    """
    i = 0
    bare_candidate = None

    while i < len(args):
        token = args[i]

        # --port N  /  -p N
        if token in ('--port', '-p') and i + 1 < len(args):
            try:
                return int(args[i + 1])
            except ValueError:
                pass

        # --port=N
        if token.startswith('--port='):
            try:
                return int(token.split('=', 1)[1])
            except ValueError:
                pass

        # --bind HOST:PORT  (gunicorn / hypercorn)
        if token in ('--bind', '-b') and i + 1 < len(args):
            val = args[i + 1]
            if ':' in val:
                try:
                    return int(val.rsplit(':', 1)[1])
                except ValueError:
                    pass

        # --bind=HOST:PORT
        if token.startswith('--bind='):
            val = token.split('=', 1)[1]
            if ':' in val:
                try:
                    return int(val.rsplit(':', 1)[1])
                except ValueError:
                    pass

        # HOST:PORT bare token  (e.g. 0.0.0.0:8000  or  just :8000)
        if ':' in token and not token.startswith('-'):
            try:
                port_part = int(token.rsplit(':', 1)[1])
                if 1024 <= port_part <= 65535:
                    bare_candidate = port_part
            except ValueError:
                pass

        # bare 4-5 digit integer
        if token.isdigit() and 4 <= len(token) <= 5:
            try:
                port_val = int(token)
                if 1024 <= port_val <= 65535:
                    bare_candidate = port_val
            except ValueError:
                pass

        i += 1

    if bare_candidate is not None:
        return bare_candidate

    # Fall back to framework default
    if args:
        first = args[0]
        if first in FRAMEWORK_PORTS:
            return FRAMEWORK_PORTS[first]
        # e.g. args = ['python', 'manage.py', ...]
        for token in args:
            basename = token.split('/')[-1].split('\\')[-1]
            if basename in FRAMEWORK_PORTS:
                return FRAMEWORK_PORTS[basename]

    return None
