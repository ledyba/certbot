"""DNS Authenticator for Value Domain DNS."""
import logging

from requests.exceptions import HTTPError
from lexicon.providers import valuedomain
import zope.interface

from certbot import interfaces
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

APIKEY_URL = "https://www.value-domain.com/vdapi/"


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Value Domain DNS

    This Authenticator uses the Value Domain API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Value Domain for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=90)
        add('credentials', help='Value Domain credentials file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Value Domain API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Value Domain API token',
            {
                'api-token': \
                    'API token for Value Domain API obtained from {0}'.format(APIKEY_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_valuedomain_client().add_txt_record(
            domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_valuedomain_client().del_txt_record(
            domain, validation_name, validation)

    def _get_valuedomain_client(self):
        return _ValueDomainLexiconClient(
            self.credentials.conf('api-token'),
            self.ttl
        )


class _ValueDomainLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Value Domain via Lexicon.
    """

    def __init__(self, api_token, ttl):
        super(_ValueDomainLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('valuedomain', {
            'ttl': ttl,
        }, {
            'auth_token': api_token,
        })

        self.provider = valuedomain.Provider(config)

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return None  # Expected errors when zone name guess is wrong
        return super(_ValueDomainLexiconClient, self)._handle_http_error(e, domain_name)

    def _find_domain_id(self, domain):
        domain_name_guesses = dns_common.base_domain_name_guesses(domain)
        for domain_name in domain_name_guesses:
            # Value Domain uses "exmaple.com" as a ID for "*.subdomain.example.com"
            if len(domain_name.split(".")) != 2:
                continue

            try:
                if hasattr(self.provider, 'options'):
                    # For Lexicon 2.x
                    self.provider.options['domain'] = domain_name
                else:
                    # For Lexicon 3.x
                    self.provider.domain = domain_name

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                result = self._handle_http_error(e, domain_name)

                if result:
                    raise result
            except Exception as e:  # pylint: disable=broad-except
                result = self._handle_general_error(e, domain_name)

                if result:
                    raise result  # pylint: disable=raising-bad-type
        raise errors.PluginError('Unable to determine zone identifier for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))
