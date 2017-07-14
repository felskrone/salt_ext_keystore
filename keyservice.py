import redis
import logging
from salt.log import setup_console_logger
from salt.log.setup import logging as salt_logging
import os

logger = salt_logging.getLogger(__name__)
log = logging.getLogger(__name__)

class RedisKeyService(object):
    '''
    Keyservice in a redis-database.
    '''
    def __init__(self, **kwargs):
        self.opts = opts
        self.rserver = opts.get('redis_server', 'localhost')
        self.rport = opts.get('redis_port', 6379)
        self.rdb = opts.get('redis_db', None)
        self.rpass = opts.get('redis_password', None)

        self.conn = redis.StrictRedis(self.rserver, self.rport, self.rdb, self.rpass)

    #
    # Redis related functions for interacting with redis-db
    #
    def reset(self):
        '''
        Delete all keys present in redis-db
        '''
        for key in self.scan('*'):
            self.delete_key(key)


    def exists(self, key):
        '''
        Check if key exists in redis-db
        '''
        return self.conn.exists(key)


    def delete_key(self, key):
        '''
        Delete a key in redis-db
        '''
        return self.conn.delete(key)


    def get_key(self, key, host=None, port=None, db=None, password=None):
        '''
        Return a key from redis-db
        '''
        return self.conn.get(key)


    def set_key(self, key, value, host=None, port=None, db=None, password=None):
        '''
        Set a key to a value in redis-db
        '''
        return self.conn.set(key, value)


    def scan(self, pattern):
        '''
        Set for keys matching pattern and return as list
        '''
        return [ x for x in self.conn.scan_iter(match=pattern) ]


    #
    # Salt related functions for key-handling
    #
    def auth(self, minion, skey):
        '''
        Authorize/Deny a minion either by key, auto_reject/accept, open_mode, etc.
        '''
        log.info('Authenticaton request from {0}'.format(minion))
        if self.opts['open_mode']:
            # open mode is turned on, nuts to checks and overwrite whatever
            log.info('Open mode, passing through...')
            return True

        elif self.rejected(minion):
            # The key has been rejected, don't place it in pending
            log.info('Public key rejected for minion {0}. Key is present in '
                     'rejection list.\n'.format(minion))
            return False

        elif self.exists('minions:{0}'.format(minion)):
            # The key has been accepted, check it
            if skey == self.get_key('minions:{0}'.format(minion)):
                pass
            else:
                # put denied minion key into minions_denied
                log.error(
                    'Authentication attempt from {0} failed, the public '
                    'keys did not match. This may be an attempt to compromise '
                    'the Salt cluster.\n'.format(minion))
                self.set_key('minions_denied:{0}'.format(minion), skey)
                return False

        elif not self.exists('minions_pre:{0}'.format(minion)):
            # The key has not been accepted, this is a new minion

            if self.auto_reject(minion):
                log.info('New public key for {0} rejected via autoreject_entry\n'.format(minion))
                return False

            elif not self.auto_sign(minion):
                log.info('New public key for {0} placed in pending\n'.format(minion))
                self.set_key('minions_pre:{0}'.format(minion), skey)
                return False

            else:
                pass

        elif self.exists('minions_pre:{0}'.format(minion)):
            if self.auto_reject(minion):
                self.set_key('minions_rejected:{0}'.format(minion), skey)
                self.delete_key('minions_pre:{0}'.format(minion))
                log.info('Pending public key for {0} rejected via '
                         'autoreject_file'.format(minion))

            elif not self.auto_sign(minion):
                # This key is in the pending dir and is not being auto-signed.
                # Check if the keys are the same and error out if this is the
                # case. Otherwise log the fact that the minion is still
                # pending.

                if skey == self.get_key('minions_pre:{0}'.format(minion)):
                    log.info(
                        'Authentication failed from host {0}, the key is in '
                        'pending and needs to be accepted with salt-key '
                        '-a {id}'.format(minion))
                    return False
                else:
                    log.error(
                        'Authentication attempt from {0} failed, the public '
                        'key in pending did not match. This may be an '
                        'attempt to compromise the Salt cluster.'
                            .format(minion))
                    return False
            else:
                # This key is in pending and has been configured to be
                # auto-signed. Check to see if it is the same key, and if
                # so, pass on doing anything here, and let it get automatically
                # accepted below.
                    if skey == self.get_key('minions_pre:{0}'.format(minion)):
                        log.debug('Passing on, minions gets auto_signed...')
                    else:
                        log.error(
                            'Authentication attempt from {0} failed, the public '
                            'key in pending did not match. This may be an '
                            'attempt to compromise the Salt cluster.'
                                .format(minion))
                        return False

        else:
            # Something happened that I have not accounted for, FAIL!
            log.warning('Unaccounted for authentication failure')
            return False

        log.info('Authentication accepted from {0}\n'.format(minion))

        if not self.exists('minions:{0}'.format(minion)) and not self.opts['open_mode']:
            self.accept(minion, skey)

        elif self.opts['open_mode']:
            self.accept(minion, skey)


    def minions(self):
        '''
        Return a list of all minions present. Required for interaction with salt-key
        '''
        ret = {}

        states = [
            'minions',
            'minions_pre',
            'minions_denied',
            'minions_rejected'
        ]

        for s in states:
            ret[s] = [ x.split(':')[1] for x in self.scan(s + ':*') ]

        return ret


    def pre(self, minion, pre):
        '''
        Return a list of all minions in pre
        '''
        return self.exists('minions_pre:{0}'.format(minion))


    def rejected(self, minion):
        '''
        Return a list of all minions to be rejected
        '''
        return self.exists('minions_rejected:{0}'.format(minion))


    def auto_reject(self, minion):
        '''
        Check if a minion it to be automatically rejected
        '''
        return self.exists('minions_autoreject:{0}'.format(minion))


    def auto_sign(self, minion):
        '''
        Check if a minion it to be automatically accepted
        '''
        return self.exists('minions_autosign:{0}'.format(minion))


    def denied(self):
        '''
        Return a list of denied minions, used for interacting with salt-key
        '''
        return {'minions_denied': [ x.split(':')[1] for x in self.scan('minions_denied:*')] }


    def accept(self, minion, key):
        '''
        Accept a minion with its key
        '''
        states = [
            'minions_pre:{0}',
            'minions_denied:{0}',
            'minions_rejected:{0}'
        ]

        for s in states:
            if self.exists(s.format(minion)):
                self.delete_key(s.format(minion))

        return self.set_key('minions:{0}'.format(minion), key)



class FSKeyService(object):
    '''
    Keyservice in the Filesystem.  Would implement the logic currently
    present in salt.transports.mixins.auth.AESReqServerMixin._auth()
    '''
    def __init__(self, **kwargs):
        self.opts = kwargs

    def minions(self):
        ret = {}

        for root, dirnames, fnames in os.walk('/etc/salt/pki/master'):
            for dirn in dirnames:
                ret[dirn] = os.listdir(os.path.join(root, dirn))
        return ret




class KeyServiceFactory(object):
    '''
    Instantiates Keyservice object depending on
    the settings in the masters config file
    '''
    def factory(self, **kwargs):

        if 'keyservice' in kwargs:
            ks = kwargs['keyservice']

            if ks == 'redis':
                log.info('Creating RedisKeyservice-instance...\n')
                return RedisKeyService(**kwargs)
            elif ks == 'mysql':
                log.info('Creating MysqlKeyservice-instance...')
            else:
                log.error('Unknown KeyService-configuration...')
        else:
            log.debug('Creating (default) FileKeystoreService-instance...')
            return FSKeyService(**kwargs)



class KeyserviceMixin(object):
    '''
    Class to be mixed into transports.mixins.auth.AESReqServerMixin
    to abstract key-authentication into other services.
    '''
    def __init__(self, **kwargs):
        self.auth_service = KeyServiceFactory().factory(**kwargs)

    def auth(self, minion, key):
        return self.auth_service.auth(minion, key)

    def denied(self):
        return self.auth_service.denied()

    def minions(self):
        return self.auth_service.minions()

    def accept(self, minion, key):
        return self.auth_service.accept(minion, key)

#    def auto_sign()...
#    def auto_reject()...
#    def pre()...
#    etc.

#
# Sample interaction with the KeyService
#
if __name__ == '__main__':

    setup_console_logger(log_level='debug')

    log.info('Sample interaction with FileKeyService...')

    ks = KeyserviceMixin()
    log.info('Listing minions...')

    for state, minions in sorted(ks.minions().iteritems()):
        log.info('\t{0}: {1}'.format(state, minions))


    log.info('\n\n')
    log.info('Sample interaction with RedisKeyService...')

    # Define options to work with redis
    opts = {
        'redis_server': 'localhost',
        'redis_port': 6379,
        'redis_db': None,
        'redis_pass': None,
        'keyservice': 'redis',
        'open_mode': False
    }

    p = RedisKeyService(**opts)
    log.info('Resetting the redis-store...')
    p.reset()

    ks = KeyserviceMixin(**opts)

    test_key_ok = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXhXAKyE8Dr3Cwyjw6q4
E45DHQZZDZ7pCuHZPzs13YSfUbeVAE0Bq5gD4wzXxHynRegvJgKLWyRwtq0+YzYP
jqlCiUC6H3GPk21g5HyaUuWf+xJEMp+XhC/f4F83jjRlRDN5RHPMC3btNkG1ESnS
t5+wwuqyQg2IHNPuH8YHQPR6ZVwoHMpPciDodsis1QQ8oslFPo+/0YTQb40W9kzK
npjpOvaulWjtgzQNsEknjDYE4Bma4akIDEEkdyD2jwJkmUHKUYEow27iZ7iYyH9+
lYM1xdglauPWejZAUbuMnBmseQlM4Io+eRagK/RQG9dZ4lk7hvpYo6Z8pQ4ezuj0
gQIDAQAB
-----END PUBLIC KEY-----
"""

    test_key_other = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXhXAKyE8Dr3Cwyjw6q4
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
gQIDAQAB
-----END PUBLIC KEY-----
"""

    log.info('Adding regular accepted minion server11.mydomain.org')
    ks.accept('server11.mydomain.org', test_key_ok)

    log.info('Adding minion areject.mydomain.org to get auto-rejected')
    p.set_key('minions_autoreject:areject.mydomain.org', '')

    log.info('Adding minion asign.mydomain.org to minions_autosign')
    p.set_key('minions_autosign:asign.mydomain.org', '')

    log.info('Adding minion rejected.mydomain.org to minions_rejected')
    p.set_key('minions_rejected:rejected.mydomain.org', '')

    log.info('Listing minions...')
    for state, minions in sorted(ks.minions().iteritems()):
        log.info('\t{0}: {1}'.format(state, minions))

    log.info('Authorizing with server11.mydomain.org against KeyService (auth_ok)')
    ks.auth('server11.mydomain.org', test_key_ok)

    log.info('Authorizing with areject.mydomain.org against KeyService (auto_rejected)')
    ks.auth('areject.mydomain.org', test_key_ok)

    log.info('Authorizing with asign.mydomain.org against KeyService (auto_signed)')
    ks.auth('asign.mydomain.org', test_key_ok)

    log.info('Authorizing with rejected.mydomain.org against KeyService (rejected)')
    ks.auth('rejected.mydomain.org', test_key_ok)

    log.info('Authorizing with server11.mydomain.org with different key (denied)')
    ks.auth('server11.mydomain.org', test_key_other)
    log.info('Listing minions_denied...')
    log.info(ks.denied())
    log.info('')

    log.info('Authorizing with new minion other.mydomain.org against KeyService (pending)')
    ks.auth('other.mydomain.org', test_key_other)

    log.info('Listing minions...')
    for state, minions in sorted(ks.minions().iteritems()):
        log.info('\t{0}: {1}'.format(state, minions))

