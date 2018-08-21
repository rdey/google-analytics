<?php

/*
 * This file is part of the Wid'op package.
 *
 * (c) Wid'op <contact@widop.com>
 *
 * For the full copyright and license information, please read the LICENSE
 * file that was distributed with this source code.
 */

namespace Widop\GoogleAnalytics;

use Psr\Cache\CacheItemPoolInterface;
use Http\Client\HttpClient;

/**
 * Google analytics client.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class Client
{
    /** @const The google OAuth scope. */
    const SCOPE = 'https://www.googleapis.com/auth/analytics.readonly';

    /** @var string */
    protected $clientId;

    /** @var string */
    protected $privateKey;

    /** @var HttpClient */
    private $httpClient;

    /** @var string */
    protected $url;

    /** @var string */
    protected $accessToken;

    /** @var \Psr\Cache\CacheItemPoolInterface */
    protected $cacheItemPool;

    /**
     * Creates a client.
     *
     * @param string                                              $clientId       The client ID.
     * @param string                                              $privateKey     The base64 representation of the private key.
     * @param HttpClient                                          $httpClient     The http client.
     * @param string                                              $url            The google analytics service url.
     * @param \Psr\Cache\CacheItemPoolInterface                   $cacheItemPool  The accessToken cache item pool.
     */
    public function __construct(
        $clientId,
        $privateKey,
        HttpClient $httpClient = null,
        $url = 'https://accounts.google.com/o/oauth2/token',
        CacheItemPoolInterface $cacheItemPool
    ) {
        $this->setClientId($clientId);
        $this->setPrivateKey($privateKey);
        $this->httpClient = $httpClient;
        $this->setUrl($url);
        $this->cacheItemPool = $cacheItemPool;
    }

    /**
     * Gets the client ID.
     *
     * @return string The client ID.
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Sets the client ID.
     *
     * @param string $clientId The client ID.
     *
     * @return \Widop\GoogleAnalytics\Client The client.
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * Gets the base64 representation of the private key.
     *
     * @return string The base64 representation of the private key
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * Sets the base64 representation of the private key
     *
     * @param string $privateKey The base64 representation of the private key
     *
     * @throws \Widop\GoogleAnalytics\Exception\GoogleAnalyticsException If the private key does not exist.
     *
     * @return \Widop\GoogleAnalytics\Client The client.
     */
    public function setPrivateKey($privateKey)
    {
        if (is_null($privateKey)) {
            throw GoogleAnalyticsException::invalidPrivateKey();
        }

        $this->privateKey = $privateKey;

        return $this;
    }

    /**
     * Gets the http adapter.
     *
     * @return \Widop\HttpAdapterBundle\Model\HttpAdapterInterface The http adapter.
     */
    public function getHttpClient()
    {
        return $this->httpClient;
    }

    /**
     * Gets the google analytics service url.
     *
     * @return string The google analytics service url.
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * Sets the google analytics service url.
     *
     * @param string $url The google analytics service url.
     *
     * @return \Widop\GoogleAnalytics\Client The client.
     */
    public function setUrl($url)
    {
        $this->url = $url;

        return $this;
    }

    /**
     * Gets the google OAuth access token.
     *
     * @throws \Widop\GoogleAnalytics\Exception\GoogleAnalyticsException If the access token can not be retrieved.
     *
     * @return string The access token.
     */
    public function getAccessToken()
    {
        $item = $this->cacheItemPool->getItem('widop_access_token');

        if (!$item->isHit()) {
            $headers = array('Content-Type' => 'application/x-www-form-urlencoded');
            $content = http_build_query(array(
                'grant_type'     => 'assertion',
                'assertion_type' => 'http://oauth.net/grant_type/jwt/1.0/bearer',
                'assertion'      => $this->generateJsonWebToken(),
            ));

            $response = json_decode($this->httpClient->post($this->url, $headers, $content)->getBody());

            if (isset($response->error)) {
                throw GoogleAnalyticsException::invalidAccessToken($response->error);
            }

            $accessToken = $response->access_token;

            $item->set($accessToken);
            $item->expiresAfter((int) $response->expires_in);
            $this->cacheItemPool->save($item);
        }

        return $item->get();
    }

    /**
     * Generates the JWT in order to get the access token.
     *
     * @return string The Json Web Token (JWT).
     */
    protected function generateJsonWebToken()
    {
        $exp = new \DateTime('+1 hours');
        $iat = new \DateTime();

        $jwtHeader = base64_encode(json_encode(array('alg' => 'RS256', 'typ' => 'JWT')));

        $jwtClaimSet = base64_encode(
            json_encode(
                array(
                    'iss'   => $this->clientId,
                    'scope' => self::SCOPE,
                    'aud'   => $this->url,
                    'exp'   => $exp->getTimestamp(),
                    'iat'   => $iat->getTimestamp(),
                )
            )
        );

        $jwtSignature = base64_encode($this->generateSignature($jwtHeader.'.'.$jwtClaimSet));

        return sprintf('%s.%s.%s', $jwtHeader, $jwtClaimSet, $jwtSignature);
    }

    /**
     * Generates the JWT signature according to the private key file and the JWT content.
     *
     * @param string $jsonWebToken The JWT content.
     *
     * @throws \Widop\GoogleAnalytics\Exception\GoogleAnalyticsException If an error occured when generating the signature.
     *
     * @return string The JWT signature.
     */
    protected function generateSignature($jsonWebToken)
    {
        if (!function_exists('openssl_x509_read')) {
            throw GoogleAnalyticsException::invalidOpenSslExtension();
        }

        $certificate = base64_decode($this->privateKey);

        $certificates = array();
        if (!openssl_pkcs12_read($certificate, $certificates, 'notasecret')) {
            throw GoogleAnalyticsException::invalidPKCS12File();
        }

        if (!isset($certificates['pkey']) || !$certificates['pkey']) {
            throw GoogleAnalyticsException::invalidPKCS12Format();
        }

        $ressource = openssl_pkey_get_private($certificates['pkey']);

        if (!$ressource) {
            throw GoogleAnalyticsException::invalidPKCS12PKey();
        }

        $signature = null;
        if (!openssl_sign($jsonWebToken, $signature, $ressource, 'sha256')) {
            throw GoogleAnalyticsException::invalidPKCS12Signature();
        }

        openssl_pkey_free($ressource);

        return $signature;
    }
}
