import operator
import os
import re
import subprocess
import sys
import time
from distutils.version import StrictVersion

from aioresponses import aioresponses
import json as json_util


from semantic_version import Spec, Version


class ServerManager(object):

    def __init__(self, config_path, client):
        self.config_path = config_path
        self.client = client
        self.keys = None
        self.root_token = None

        self._process = None

    def start(self):
        command = ['vault', 'server', '-config=' + self.config_path]

        self._process = subprocess.Popen(command,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                self.client.is_initialized()
                return
            except Exception as ex:
                print('Waiting for Vault to start')

                time.sleep(.5)

                attempts_left -= 1
                last_exception = ex
        raise last_exception
        # raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    def stop(self):
        self.client.close()
        self._process.kill()

    def initialize(self):
        assert not self.client.is_initialized()

        result = self.client.initialize()

        assert self.client.is_initialized()

        self.root_token = result['root_token']
        self.keys = result['keys']

    def unseal(self):
        return self.client.unseal_multi(self.keys)


VERSION_REGEX = re.compile(r'Vault v([\d.]+)')


def match_version(spec):
    output = subprocess.check_output(['vault', 'version']).decode('ascii')
    version = Version(VERSION_REGEX.match(output).group(1))

    return Spec(spec).match(version)


class RequestsMocker(aioresponses):

    def __init__(self):
        super(RequestsMocker, self).__init__()

    def register_uri(self, method='GET', url='', status_code=200, json=None):
        if json:
            json = json_util.dumps(json)
        else:
            json = ''
        if method == 'GET':
            self.get(url=url, status=status_code, body=json)
        if method == 'POST':
            self.post(url=url, status=status_code, body=json)
        if method == 'DELETE':
            self.delete(url=url, status=status_code, body=json)


def decode_generated_root_token(encoded_token, otp):
    """Decode a newly generated root token via Vault CLI.
    :param encoded_token: The token to decode.
    :type encoded_token: str | unicode
    :param otp: OTP code to use when decoding the token.
    :type otp: str | unicode
    :return: The decoded root token.
    :rtype: str | unicode
    """
    command = ['vault']
    if vault_version_ge('0.9.6'):
        # before Vault ~0.9.6, the generate-root command was the first positional argument
        # afterwards, it was moved under the "operator" category
        command.append('operator')

    command.extend(
        [
            'generate-root',
            '-address', 'https://127.0.0.1:8200',
            '-tls-skip-verify',
            '-decode', encoded_token,
            '-otp', otp,
        ]
    )
    process = subprocess.Popen(**get_popen_kwargs(
        args=command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ))

    stdout, stderr = process.communicate()

    new_token = stdout.replace('Root token:', '')
    new_token = new_token.strip()
    return new_token


def get_popen_kwargs(**popen_kwargs):
    """Helper method to add `encoding='utf-8'` to subprocess.Popen when we're in Python 3.x.
    :param popen_kwargs: List of keyword arguments to conditionally mutate
    :type popen_kwargs: **kwargs
    :return: Conditionally updated list of keyword arguments
    :rtype: dict
    """
    if sys.version_info[0] >= 3:
        popen_kwargs['encoding'] = 'utf-8'
    return popen_kwargs


def vault_version_ge(supported_version):
    return if_vault_version(supported_version, comparison=operator.ge)


def get_installed_vault_version():
    command = ['vault', '-version']
    process = subprocess.Popen(**get_popen_kwargs(args=command, stdout=subprocess.PIPE))
    output, _ = process.communicate()
    version = output.strip().split()[1].lstrip('v')
    # replace any '-beta1' type substrings with a StrictVersion parsable version. E.g., 1.0.0-beta1 => 1.0.0b1
    version = version.replace('-', '').replace('beta', 'b')
    return version


def if_vault_version(supported_version, comparison=operator.lt):
    current_version = os.getenv('HVAC_VAULT_VERSION')
    if current_version is None or current_version.lower() == 'head':
        current_version = get_installed_vault_version()

    return comparison(StrictVersion(current_version), StrictVersion(supported_version))


def get_generate_root_otp():
    """Get a appropriate OTP for the current Vault version under test.
    :return: OTP to use in generate root operations
    :rtype: str
    """
    if vault_version_ge('1.0.0'):
        test_otp = 'ygs0vL8GIxu0AjRVEmJ5jLCVq8'
    else:
        test_otp = 'RSMGkAqBH5WnVLrDTbZ+UQ=='
    return test_otp
