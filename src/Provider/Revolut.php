<?php

namespace League\OAuth2\Client\Provider;

use Exception;
use InvalidArgumentException;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Revolut extends AbstractProvider
{
    use BearerAuthorizationTrait;
    
    public $defaultScopes = ['READ'];
    
    protected $privateKey;
    protected $isSandbox = false;
    
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (empty($options['privateKey'])) {
            throw new InvalidArgumentException('Required option not passed: "privateKey"');
        }
        
        parent::__construct($options, $collaborators);
    }
    
    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return (bool) $this->isSandbox
            ? 'https://sandbox-business.revolut.com/app-confirm'
            : 'https://business.revolut.com/app-confirm';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return (bool) $this->isSandbox
            ? 'https://sandbox-b2b.revolut.com/api/1.0/auth/token'
            : 'https://b2b.revolut.com/api/1.0/auth/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     * @throws Exception
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        throw new Exception('Resource owner details not available for Revolut.');
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return $this->defaultScopes;
    }
    
    /**
     * Checks a provider response for errors.
     *
     * @param ResponseInterface $response
     * @param array|string $data Parsed response data
     * @return void
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw new IdentityProviderException(
                array_key_exists('error_description', $data)
                    ? $data['error_description'] : $response->getReasonPhrase(),
                array_key_exists('code', $data)
                    ? $data['code'] : $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param array $response
     * @param AccessToken $token
     * @return ResourceOwnerInterface
     * @throws Exception
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        throw new Exception('Resource owner details not available for Revolut.');
    }

    /**
     * @param mixed $grant
     * @param array $options
     * @return AccessTokenInterface
     * @throws IdentityProviderException
     */
    public function getAccessToken($grant, array $options = [])
    {
        $time = new DateTimeImmutable();
        $config = Configuration::forSymmetricSigner(new Sha256(), $this->getPrivateKey());

        $token = $config->builder()
            ->issuedBy(parse_url($this->redirectUri, PHP_URL_HOST))
            ->permittedFor('https://revolut.com')
            ->issuedAt($time)
            ->expiresAt($time->modify('+1 hour'))
            ->withHeader('alg', 'RS256')
            ->relatedTo($this->clientId)
            ->getToken($config->signer(), $config->signingKey());
        
        $options += [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $token->toString()
        ];
        
        return parent::getAccessToken($grant, $options);
    }

    /**
     * @return Key
     */
    public function getPrivateKey()
    {
        return InMemory::file($this->privateKey);
    }
}
