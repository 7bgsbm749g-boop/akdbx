"""CLI side of the optional private save page lifetime (``--valid-minutes``)."""
import argparse
import re

from .writes import PAGE_LIFETIME_PROTOCOL, PAGE_MINUTES_DEFAULT, PAGE_MINUTES_MAX

RECEIPT = {'ok', 'state', 'write_handle', 'private_url'}
LIFETIME = {'expires_in', 'expires_at'}


def minutes(text):
    """A whole number of minutes from 1 to PAGE_MINUTES_MAX."""
    if not re.fullmatch('[0-9]{1,3}', text) or not 1 <= int(text) <= PAGE_MINUTES_MAX:
        raise argparse.ArgumentTypeError(f'use a whole number of minutes from 1 to {PAGE_MINUTES_MAX}')
    return int(text)


def add_argument(parser):
    parser.add_argument('--valid-minutes', type=minutes, metavar='N',
                        help=f'keep the private page valid for N minutes (1 to {PAGE_MINUTES_MAX}); '
                             f'default: {PAGE_MINUTES_DEFAULT}. The page stays single use')


def refusal(args, caps):
    """Why the CLI does not send --valid-minutes to this broker, or None."""
    if getattr(args, 'valid_minutes', None) is None:
        return None
    if (type(caps.get('save_page_lifetime_protocol')) is not int
            or caps['save_page_lifetime_protocol'] != PAGE_LIFETIME_PROTOCOL
            or type(caps.get('save_page_max_minutes')) is not int
            or args.valid_minutes > caps['save_page_max_minutes']):
        return f'broker lacks save page lifetime protocol {PAGE_LIFETIME_PROTOCOL} for {args.valid_minutes} minutes'
    timeout = caps.get('lock_timeout_seconds')
    if type(timeout) is not int or args.valid_minutes * 60 > timeout:
        # The page stops when the vault locks; opening it does not keep the vault open.
        return (f'--valid-minutes {args.valid_minutes} is longer than the broker\'s vault lock timeout '
                f'({timeout} seconds of inactivity)')
    return None


def add_request(args, payload):
    if getattr(args, 'valid_minutes', None) is not None:
        payload['valid_minutes'] = args.valid_minutes


def valid_receipt(args, response):
    """The receipt keys and, when present, the lifetime the page got.

    A broker without the lifetime protocol sends no expiry; the CLI sends
    ``valid_minutes`` only to a broker that has it, so then it is required.
    """
    requested = getattr(args, 'valid_minutes', None)
    if set(response) == RECEIPT:
        return requested is None
    # The default page is cut to a vault lock timeout below five minutes.
    seconds = response.get('expires_in')
    return (set(response) == RECEIPT | LIFETIME
            and type(seconds) is int
            and (1 <= seconds <= 60 * PAGE_MINUTES_DEFAULT if requested is None else seconds == 60 * requested)
            and isinstance(response['expires_at'], str)
            and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', response['expires_at']) is not None)
