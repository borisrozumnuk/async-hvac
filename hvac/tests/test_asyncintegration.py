from asynctest import TestCase

import asyncio

from hvac import Client, exceptions
from hvac.tests import util

loop = asyncio.get_event_loop()


def create_client(sync=False, **kwargs):
    return Client(url='https://127.0.0.1:8200',
                  cert=('test/client-cert.pem', 'test/client-key.pem'),
                  verify='test/server-cert.pem',
                  loop=IntegrationTest.loop,
                  sync=sync,
                  **kwargs)


def async_test(f):
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        loop.run_until_complete(future)
    return wrapper


class IntegrationTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.manager = util.ServerManager(
            config_path='test/vault-tls.hcl',
            client=create_client(sync=True))
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()

    def root_token(self):
        cls = type(self)
        return cls.manager.root_token

    async def setUp(self):
        self.client = create_client(token=self.root_token())

    async def tearDown(self):
        await self.client.close()

    async def test_unseal_multi(self):
        cls = type(self)

        await self.client.seal()

        keys = cls.manager.keys

        result = await self.client.unseal_multi(keys[0:2])

        assert result['sealed']
        assert result['progress'] == 2

        result = await self.client.unseal_multi(keys[2:3])

        assert not result['sealed']

    async def test_seal_unseal(self):
        cls = type(self)

        assert not (await self.client.is_sealed())

        await self.client.seal()

        assert (await self.client.is_sealed())

        cls.manager.unseal()

        assert not (await self.client.is_sealed())

    async def test_ha_status(self):
        assert 'ha_enabled' in (await self.client.ha_status)

    async def test_generic_secret_backend(self):
        await self.client.write('secret/foo', zap='zip')
        result = await self.client.read('secret/foo')

        assert result['data']['zap'] == 'zip'

        await self.client.delete('secret/foo')

    async def test_list_directory(self):
        await self.client.write('secret/test-list/bar/foo', value='bar')
        await self.client.write('secret/test-list/foo', value='bar')
        result = await self.client.list('secret/test-list')

        assert result['data']['keys'] == ['bar/', 'foo']

        await self.client.delete('secret/test-list/bar/foo')
        await self.client.delete('secret/test-list/foo')

    async def test_write_with_response(self):
        await self.client.enable_secret_backend('transit')

        plaintext = 'test'

        await self.client.write('transit/keys/foo')

        result = await self.client.write('transit/encrypt/foo', plaintext=plaintext)
        ciphertext = result['data']['ciphertext']

        result = await self.client.write('transit/decrypt/foo', ciphertext=ciphertext)
        assert result['data']['plaintext'] == plaintext

    async def test_wrap_write(self):
        if 'approle/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend("approle")
        await self.client.write("auth/approle/role/testrole")

        result = await self.client.write('auth/approle/role/testrole/secret-id', wrap_ttl="10s")

        assert 'token' in result['wrap_info']

        await self.client.unwrap(result['wrap_info']['token'])
        await self.client.disable_auth_backend("approle")

    async def test_read_nonexistent_key(self):
        assert not (await self.client.read('secret/I/dont/exist'))

    async def test_auth_backend_manipulation(self):
        assert 'github/' not in (await self.client.list_auth_backends())

        await self.client.enable_auth_backend('github')
        assert 'github/' in (await self.client.list_auth_backends())

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('github')
        assert 'github/' not in (await self.client.list_auth_backends())

    async def test_secret_backend_manipulation(self):
        assert 'test/' not in (await self.client.list_secret_backends())

        await self.client.enable_secret_backend('generic', mount_point='test')
        assert 'test/' in (await self.client.list_secret_backends())

        await self.client.remount_secret_backend('test', 'foobar')
        assert 'test/' not in (await self.client.list_secret_backends())
        assert 'foobar/' in (await self.client.list_secret_backends())

        self.client.token = self.root_token()
        await self.client.disable_secret_backend('foobar')
        assert 'foobar/' not in (await self.client.list_secret_backends())

    async def test_audit_backend_manipulation(self):
        assert 'tmpfile/' not in (await self.client.list_audit_backends())

        options = {
            'path': '/tmp/vault.audit.log'
        }

        await self.client.enable_audit_backend('file', options=options, name='tmpfile')
        assert 'tmpfile/' in (await self.client.list_audit_backends())

        self.client.token = self.root_token()
        await self.client.disable_audit_backend('tmpfile')
        assert 'tmpfile/' not in (await self.client.list_audit_backends())

    async def prep_policy(self, name):
        text = """
        path "sys" {
          policy = "deny"
        }

        path "secret" {
          policy = "write"
        }
        """
        obj = {
            'path': {
                'sys': {
                    'policy': 'deny'},
                'secret': {
                    'policy': 'write'}
            }
        }

        await self.client.set_policy(name, text)

        return text, obj

    async def test_policy_manipulation(self):
        assert 'root' in (await self.client.list_policies())
        assert (await self.client.get_policy('test')) is None

        policy, parsed_policy = await self.prep_policy('test')
        assert 'test' in (await self.client.list_policies())
        assert policy == (await self.client.get_policy('test'))
        assert parsed_policy == (await self.client.get_policy('test', parse=True))

        await self.client.delete_policy('test')
        assert 'test' not in (await self.client.list_policies())

    async def test_json_policy_manipulation(self):
        assert 'root' in (await self.client.list_policies())

        await self.prep_policy('test')
        assert 'test' in (await self.client.list_policies())

        await self.client.delete_policy('test')
        assert 'test' not in (await self.client.list_policies())

    async def test_auth_token_manipulation(self):
        result = await self.client.create_token(lease='1h', renewable=True)
        assert result['auth']['client_token']

        lookup = await self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

        renew = await self.client.renew_token(lookup['data']['id'])
        assert result['auth']['client_token'] == renew['auth']['client_token']

        await self.client.revoke_token(lookup['data']['id'])

        try:
            lookup = await self.client.lookup_token(result['auth']['client_token'])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    async def test_userpass_auth(self):
        if 'userpass/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('userpass')

        await self.client.enable_auth_backend('userpass')

        await self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = await self.client.auth_userpass('testuser', 'testpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('userpass')

    async def test_create_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('userpass')

        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        # Test ttl:
        self.client.token = self.root_token()
        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root', ttl='10s')
        self.client.token = result['auth']['client_token']

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert result['auth']['lease_duration'] == 10

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('userpass')

    async def test_delete_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('userpass')

        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.root_token()
        await self.client.delete_userpass('testcreateuser')
        with self.assertRaises(exceptions.InvalidRequest):
            await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

    async def test_app_id_auth(self):
        if 'app-id/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('app-id')

        await self.client.enable_auth_backend('app-id')

        await self.client.write('auth/app-id/map/app-id/foo', value='not_root')
        await self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = await self.client.auth_app_id('foo', 'bar')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('app-id')

    async def test_create_app_id(self):
        if 'app-id/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('app-id')

        await self.client.create_app_id('testappid', policies='not_root', display_name='displayname')

        result = await self.client.read('auth/app-id/map/app-id/testappid')
        lib_result = await self.client.get_app_id('testappid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testappid'
        assert result['data']['display_name'] == 'displayname'
        assert result['data']['value'] == 'not_root'
        await self.client.delete_app_id('testappid')
        assert (await self.client.get_app_id('testappid'))['data'] is None

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('app-id')

    async def test_create_user_id(self):
        if 'app-id/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('app-id')

        await self.client.create_app_id('testappid', policies='not_root', display_name='displayname')
        await self.client.create_user_id('testuserid', app_id='testappid')

        result = await self.client.read('auth/app-id/map/user-id/testuserid')
        lib_result = await self.client.get_user_id('testuserid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testuserid'
        assert result['data']['value'] == 'testappid'

        result = await self.client.auth_app_id('testappid', 'testuserid')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())
        self.client.token = self.root_token()
        await self.client.delete_user_id('testuserid')
        assert (await self.client.get_user_id('testuserid'))['data'] is None

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('app-id')

    async def test_create_role(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')

        result = await self.client.read('auth/approle/role/testrole')
        lib_result = await self.client.get_role('testrole')
        del result['request_id']
        del lib_result['request_id']

        assert result == lib_result
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_create_delete_role_secret_id(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        result = await self.client.get_role_secret_id('testrole', secret_id)
        assert result['data']['metadata']['foo'] == 'bar'
        await self.client.delete_role_secret_id('testrole', secret_id)
        assert (await self.client.get_role_secret_id('testrole', secret_id)) is None
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_auth_approle(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = await self.client.get_role_id('testrole')
        result = await self.client.auth_approle(role_id, secret_id)
        assert result['auth']['metadata']['foo'] == 'bar'
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_missing_token(self):
        client = create_client()
        assert not (await client.is_authenticated())
        await client.close()

    async def test_invalid_token(self):
        client = create_client(token='not-a-real-token')
        assert not (await client.is_authenticated())
        await client.close()

    async def test_illegal_token(self):
        client = create_client(token='token-with-new-line\n')
        try:
            await client.is_authenticated()
        except ValueError as e:
            assert 'Invalid header value' in str(e)
        await client.close()

    async def test_broken_token(self):
        client = create_client(token='\x1b')
        try:
            await client.is_authenticated()
        except exceptions.InvalidRequest as e:
            assert "invalid header value" in str(e)
        await client.close()

    async def test_client_authenticated(self):
        assert (await self.client.is_authenticated())

    async def test_client_logout(self):
        self.client.logout()
        assert not (await self.client.is_authenticated())

    async def test_revoke_self_token(self):
        if 'userpass/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('userpass')

        await self.client.enable_auth_backend('userpass')

        await self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = await self.client.auth_userpass('testuser', 'testpass')

        await self.client.revoke_self_token()
        assert not (await self.client.is_authenticated())

    async def test_rekey_multi(self):
        cls = type(self)

        assert not (await self.client.rekey_status)['started']

        await self.client.start_rekey()
        assert (await self.client.rekey_status)['started']

        await self.client.cancel_rekey()
        assert not (await self.client.rekey_status)['started']

        result = await self.client.start_rekey()

        keys = cls.manager.keys

        result = await self.client.rekey_multi(keys, nonce=result['nonce'])
        assert result['complete']

        cls.manager.keys = result['keys']
        cls.manager.unseal()

    async def test_rotate(self):
        status = await self.client.key_status

        await self.client.rotate()

        assert (await self.client.key_status)['term'] > status['term']

    async def test_tls_auth(self):
        await self.client.enable_auth_backend('cert')

        with open('test/client-cert.pem') as fp:
            certificate = fp.read()

        await self.client.write('auth/cert/certs/test', display_name='test',
                                     policies='not_root', certificate=certificate)

        result = await self.client.auth_tls()

    async def test_gh51(self):
        key = 'secret/http://test.com'

        await self.client.write(key, foo='bar')

        result = await self.client.read(key)

        assert result['data']['foo'] == 'bar'

    async def test_token_accessor(self):
        # Create token, check accessor is provided
        result = await self.client.create_token(lease='1h')
        token_accessor = result['auth'].get('accessor', None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = await self.client.lookup_token(token_accessor, accessor=True)
        assert lookup['data']['accessor'] == token_accessor
        assert not lookup['data']['id']

        # Revoke token using the accessor
        await self.client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = await self.client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = await self.client.lookup_token(result['auth']['client_token'])

    async def test_wrapped_token_success(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Unwrap token
        result = await self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Validate token
        lookup = await self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

    async def test_wrapped_token_intercept(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Intercept wrapped token
        _ = await self.client.unwrap(wrap['wrap_info']['token'])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            result = await self.client.unwrap(wrap['wrap_info']['token'])

    async def test_wrapped_token_cleanup(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        _token = self.client.token
        _ = await self.client.unwrap(wrap['wrap_info']['token'])
        assert self.client.token == _token

    async def test_wrapped_token_revoke(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Revoke token before it's unwrapped
        await self.client.revoke_token(wrap['wrap_info']['wrapped_accessor'], accessor=True)

        # Unwrap token anyway
        result = await self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            lookup = await self.client.lookup_token(result['auth']['client_token'])

    async def test_create_token_explicit_max_ttl(self):

        token = await self.client.create_token(ttl='30m', explicit_max_ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    async def test_create_token_max_ttl(self):

        token = await self.client.create_token(ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    async def test_token_roles(self):
        # No roles, list_token_roles == None
        before = await self.client.list_token_roles()
        assert not before

        # Create token role
        assert (await self.client.create_token_role('testrole')).status == 204

        # List token roles
        during = (await self.client.list_token_roles())['data']['keys']
        assert len(during) == 1
        assert during[0] == 'testrole'

        # Delete token role
        await self.client.delete_token_role('testrole')

        # No roles, list_token_roles == None
        after = await self.client.list_token_roles()
        assert not after

    async def test_create_token_w_role(self):
        # Create policy
        await self.prep_policy('testpolicy')

        # Create token role w/ policy
        assert (await self.client.create_token_role('testrole',
                                                         allowed_policies='testpolicy')).status == 204

        # Create token against role
        token = await self.client.create_token(lease='1h', role='testrole')
        assert token['auth']['client_token']
        assert token['auth']['policies'] == ['default', 'testpolicy']

        # Cleanup
        await self.client.delete_token_role('testrole')
        await self.client.delete_policy('testpolicy')
