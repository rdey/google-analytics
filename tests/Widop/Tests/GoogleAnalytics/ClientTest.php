<?php

/*
 * This file is part of the Wid'op package.
 *
 * (c) Wid'op <contact@widop.com>
 *
 * For the full copyright and license information, please read the LICENSE
 * file that was distributed with this source code.
 */

namespace Widop\Tests\GoogleAnalytics;

use Widop\GoogleAnalytics\Client;

/**
 * Google analytics client test.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class ClientTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\GoogleAnalytics\Client */
    protected $client;

    /** @var string */
    protected $clientId;

    /** @var string */
    protected $privateKey;

    /** @var string */
    protected $url;

    /** @var \Widop\HttpAdapterBundle\Model\HttpAdapterInterface */
    protected $httpAdapterMock;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->clientId = 'client_id';
        $this->privateKey = base64_encode(file_get_contents(__DIR__.'/Fixtures/certificate.p12'));
        $this->httpAdapterMock = $this->getMock('Widop\HttpAdapter\HttpAdapterInterface');
        $this->url = 'https://foo';

        $this->client = new Client($this->clientId, $this->privateKey, $this->httpAdapterMock, $this->url);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        unset($this->client);
        unset($this->clientId);
        unset($this->privateKey);
        unset($this->httpAdapterMock);
        unset($this->url);
    }

    public function testDefaultState()
    {
        $this->assertSame($this->clientId, $this->client->getClientId());
        $this->assertSame($this->privateKey, $this->client->getPrivateKey());
        $this->assertSame($this->httpAdapterMock, $this->client->getHttpAdapter());
        $this->assertSame($this->url, $this->client->getUrl());
    }

    public function testAccessToken()
    {
        if (!function_exists('openssl_x509_read')) {
            $this->markTestSkipped('The "openssl_x509_read" function is not available.');
        }

        $this->httpAdapterMock
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo($this->url),
                $this->equalTo(array('Content-Type' => 'application/x-www-form-urlencoded'))
            )
            ->will($this->returnValue(json_encode(array('access_token' => 'token'))));

        $this->assertSame('token', $this->client->getAccessToken());
    }

    public function testAccessTokenError()
    {
        if (!function_exists('openssl_x509_read')) {
            $this->markTestSkipped('The "openssl_x509_read" function is not available.');
        } else {
            $this->setExpectedException('Widop\GoogleAnalytics\GoogleAnalyticsException');
        }

        $this->httpAdapterMock
            ->expects($this->once())
            ->method('postContent')
            ->will($this->returnValue(json_encode(array('error' => 'error'))));

        $this->client->getAccessToken();
    }

    /**
     * @expectedException \Widop\GoogleAnalytics\GoogleAnalyticsException
     */
    public function testInvalidPrivateKey()
    {
        $this->client->setPrivateKey(null);
        $this->client->getAccessToken();
    }

    /**
     * @expectedException \Widop\GoogleAnalytics\GoogleAnalyticsException
     */
    public function testInvalidPkcs12Format()
    {
        $this->client->setPrivateKey(base64_encode(file_get_contents(__DIR__.'/Fixtures/invalid_format.p12')));
        $this->client->getAccessToken();
    }
}
