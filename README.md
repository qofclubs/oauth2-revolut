# Revolut Provider for OAuth 2.0 Client
[![Latest Version](https://img.shields.io/github/release/vdbelt/oauth2-revolut.svg?style=flat-square)](https://github.com/vdbelt/oauth2-revolut/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/vdbelt/oauth2-revolut.svg?style=flat-square)](https://packagist.org/packages/vdbelt/oauth2-revolut)

This package provides Revolut OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Installation

To install, use composer:

```
composer require vdbelt/oauth2-revolut
```

## Usage

Usage is the same as The League's OAuth client, using `\League\OAuth2\Client\Provider\Revolut` as the provider.

### Authorization Code Flow

```php
$provider = new League\OAuth2\Client\Provider\Revolut([
    'clientId'          => '{revolut-client-id}',
    'privateKey'        => 'file://{revolut-private-key-path}',
    'redirectUri'       => 'https://example.com/callback-url'
]);

if (!isset($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: '.$authUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Use this to interact with the API on the users behalf
    echo $token->getToken();
}
```

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/vdbelt/oauth2-revolut/blob/master/CONTRIBUTING.md) for details.


## Credits

- [Martin van de Belt](https://github.com/vdbelt)
- [All Contributors](https://github.com/vdbelt/oauth2-revolut/contributors)


## License

The MIT License (MIT). Please see [License File](https://github.com/vdbelt/oauth2-revolut/blob/master/LICENSE) for more information.
