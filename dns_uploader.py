import argparse
import ipaddress
import json
import logging
import time
from logging.handlers import RotatingFileHandler
from typing import Text, Tuple

import schedule
from requests import get, post
from retrying import retry

EXTERNAL_IP_FINDER_ADDR = 'https://api.ipify.org'
GOOGLE_API_ADDR = 'https://{username}:{password}@domains.google.com/nic/update?hostname={domain}&myip={ip}'
MAX_RETRIES = 3
WAIT_FIX = 2000
LOG_FILE = './dns_uploader.log'

parser = argparse.ArgumentParser()
parser.add_argument('--user')
parser.add_argument('--pw')
parser.add_argument('--domain')
parser.add_argument('--dns_config_file')

log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(
    LOG_FILE,
    mode='a',
    maxBytes=1024 *
             1024 *
             1204,
    backupCount=2)

log_handler.setLevel('INFO')
log_handler.setFormatter(log_formatter)

logger = logging.getLogger('root')
logger.setLevel('INFO')
logger.addHandler(log_handler)


def parse_dns_config_file(config_file: Text) -> Tuple[Text, Text]:
    """Parse Dynamic DNS config file in json.

    Args:
        config_file: the path of config file.
    Returns:
        A tuple of username and password.
    """
    with open(config_file, 'r') as f:
        d = json.load(f)
    return d['username'], d['password']


def parse_gmail_config_file(config_file: Text):
    # TODO: Support mail alert
    pass


class ServiceError(Exception):
    pass


class Monitor(object):
    def __init__(self, user: Text, pw: Text, domain: Text,
                 ip_finder_addr: Text = EXTERNAL_IP_FINDER_ADDR):
        self.ip_finder_addr = ip_finder_addr
        self.ip = self._resolve_ip()
        self.user = user
        self.pw = pw
        self.domain = domain

    @retry(retry_on_exception=lambda x: isinstance(
        x, ValueError), stop_max_attempt_number=MAX_RETRIES, wait_fixed=WAIT_FIX)
    def _resolve_ip(self):
        """Resolve IP by external services."""
        ip = get(self.ip_finder_addr).text
        logger.info('Current ip is %s.', ip)
        ip = ipaddress.ip_address(ip)
        return ip

    @retry(retry_on_exception=lambda x: isinstance(x, ServiceError),
           stop_max_attempt_number=MAX_RETRIES, wait_fixed=WAIT_FIX)
    def run(self):
        new_ip = self._resolve_ip()
        if self.ip == new_ip:
            logger.info('IP does not change: %s.', self.ip)
        else:
            logger.info('IP changed. Old: %s, new: %s.', self.ip, new_ip)
            self.ip = new_ip
            return_ip = self._update_ip()
            if return_ip != self.ip:
                raise ServiceError(
                    'Returned IP does not equal to current IP. Returned: %s, cur: %s',
                    return_ip,
                    self.ip)

    def _update_ip(self) -> Text:
        """Update IP by sending request to Google Domain.

        The method uses Google Domain API to update IP for dynamic DNS.
        An example of the API
        https://username:password@domains.google.com/nic/update?hostname=subdomain.yourdomain.com&myip=1.2.3.4

        Returns:
            A string representation of IP.

        Raises:
            ServiceError if an error returned by the service.
        """

        resp = post(GOOGLE_API_ADDR.format(
            username=self.user,
            password=self.pw,
            domain=self.domain,
            ip=self.ip
        )).text

        if 'good' in resp:
            # E.g. good 1.2.3.4.
            logger.info('Success update IP: %s', resp)
            return resp.split(' ')[1]
        elif 'nochg' in resp:
            # No change.
            logger.info('The IP address does not change: %s', resp)
            return resp.split(' ')[1]
        else:
            raise ServiceError(resp)

    def _send_alert(self):
        # TODO: Support mail alert
        pass


def main(args):
    if 'dns_config_file' in args:
        user, pw = parse_dns_config_file(args['dns_config_file'])
    else:
        user, pw = args['user'], args['pw']

    monitor = Monitor(user, pw, domain=args['domain'])
    monitor.run()

    schedule.every(5).minutes.do(monitor.run)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == '__main__':
    args = vars(parser.parse_args())
    main(args)
