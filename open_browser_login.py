"""Run browser login on an SSH host and open its Xiaomi login URL on this desktop.

Credentials and email codes stay on Xiaomi's website. Session tokens stay on the SSH host.
The temporary login link is consumed in memory and never printed or saved by this launcher.
"""

import argparse
import pathlib
import shlex
import subprocess
import sys
import webbrowser

from account_cloud import BindError, allowed_url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', required=True)
    parser.add_argument('--remote-dir', required=True)
    parser.add_argument('--region', choices=('cn', 'de', 'us', 'sg', 'in', 'ru'), required=True)
    args = parser.parse_args()
    if args.ssh.startswith('-'):
        parser.error('Invalid SSH destination.')
    remote = shlex.join(['python3', '-u', str(pathlib.PurePosixPath(args.remote_dir) / 'account_bind.py'),
                         'login-browser', '--region', args.region])
    process = subprocess.Popen(['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o',
        'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', args.ssh, remote],
        stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)
    try:
        assert process.stdout is not None
        for line in process.stdout:
            if line.startswith('XIAOMI_LOGIN_URL: '):
                url = allowed_url(line[len('XIAOMI_LOGIN_URL: '):].strip())
                if not webbrowser.open(url):
                    raise BindError('Could not open the default browser.')
                print('Xiaomi login page opened in the browser. Complete email verification there.', flush=True)
            else:
                print(line, end='', flush=True)
        return process.wait()
    except BaseException:
        process.terminate()
        process.wait()
        raise


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (BindError, OSError):
        print('Could not start browser login; session connection or browser error.', file=sys.stderr)
        sys.exit(1)
