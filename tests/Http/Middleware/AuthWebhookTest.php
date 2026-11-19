<?php

namespace Osiset\ShopifyApp\Test\Http\Middleware;

use Illuminate\Http\Response;
use Illuminate\Support\Facades\Request;
use Osiset\ShopifyApp\Http\Middleware\AuthWebhook as AuthWebhookMiddleware;
use Osiset\ShopifyApp\Test\TestCase;

class AuthWebhookTest extends TestCase
{
    public function testDenysForMissingShopHeader(): void
    {
        $currentRequest = Request::instance();
        $newRequest = $currentRequest->duplicate(
            // Query Params
            [],
            // Request Params
            null,
            // Attributes
            null,
            // Cookies
            null,
            // Files
            null,
            // Server vars
            // This valid referer should be ignored as there is a get variable
            array_merge(Request::server(), [
                'HTTP_X_Shopify_Hmac_Sha256' => '1234',
            ])
        );

        // Run the middleware
        $result = $this->runMiddleware(AuthWebhookMiddleware::class, $newRequest);

        // Assert we get a proper response
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $result[1]->status());
    }

    public function testDenysForMissingHmacHeader(): void
    {
        $currentRequest = Request::instance();
        $newRequest = $currentRequest->duplicate(
            // Query Params
            [],
            // Request Params
            null,
            // Attributes
            null,
            // Cookies
            null,
            // Files
            null,
            // Server vars
            // This valid referer should be ignored as there is a get variable
            array_merge(Request::server(), [
                'HTTP_X_Shopify_Shop_Domain' => 'example.myshopify.com',
            ])
        );

        // Run the middleware
        $result = $this->runMiddleware(AuthWebhookMiddleware::class, $newRequest);

        // Assert we get a proper response
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $result[1]->status());
    }

    public function testRuns(): void
    {
        $currentRequest = Request::instance();
        $newRequest = $currentRequest->duplicate(
            // Query Params
            [],
            // Request Params
            null,
            // Attributes
            null,
            // Cookies
            null,
            // Files
            null,
            // Server vars
            // This valid referer should be ignored as there is a get variable
            array_merge(Request::server(), [
                'HTTP_X_Shopify_Hmac_Sha256' => 'vhwRQys0GZozEzsl9+bjquUnCkjSE7r1YPgl9S0CY1E=',
                'HTTP_X_Shopify_Shop_Domain' => 'example.myshopify.com',
            ])
        );

        // Run the middleware
        $result = $this->runMiddleware(AuthWebhookMiddleware::class, $newRequest);

        // Assert we get a proper response
        $this->assertTrue($result[0]);
    }

    public function testRunsWithOldSecretDuringRotation(): void
    {
        $this->rotateSecret('old');

        $result = $this->runMiddleware(AuthWebhookMiddleware::class, $this->signedWebhookRequest());

        $this->assertTrue($result[0]);
    }

    public function testDeniesOldSecretWhenNotConfigured(): void
    {
        $this->rotateSecret('');

        $result = $this->runMiddleware(AuthWebhookMiddleware::class, $this->signedWebhookRequest());

        $this->assertSame(Response::HTTP_UNAUTHORIZED, $result[1]->status());
    }

    protected function rotateSecret(string $keepOld): void
    {
        $current = $this->app['config']->get('shopify-app.api_secret');
        $this->app['config']->set('shopify-app.api_secret', 'rotated-secret');
        $this->app['config']->set('shopify-app.api_secret_old', $keepOld === 'old' ? $current : '');
    }

    protected function signedWebhookRequest(): \Illuminate\Http\Request
    {
        return Request::instance()->duplicate(
            [],
            null,
            null,
            null,
            null,
            array_merge(Request::server(), [
                'HTTP_X_Shopify_Hmac_Sha256' => 'vhwRQys0GZozEzsl9+bjquUnCkjSE7r1YPgl9S0CY1E=',
                'HTTP_X_Shopify_Shop_Domain' => 'example.myshopify.com',
            ])
        );
    }
}
