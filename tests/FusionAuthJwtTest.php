<?php

use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenAlgorithmException;
use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenException;
use DaniloPolani\FusionAuthJwt\FusionAuthJwt;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

test('::decode() will throw an error if the algo is not supported', function () {
    Config::set('fusionauth.supported_algs', ['foo']);

    FusionAuthJwt::decode('jwt');
})->throws(InvalidTokenAlgorithmException::class);

test('::validate() will throw an error if the issuer is not authorized', function () {
    Config::set('fusionauth.audience', 'bar');
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => 'bar', 'iss' => 'baz']);
})->throws(InvalidTokenException::class);

test('::validate() will throw an error if the audience or client_id are not authorized', function () {
    Config::set('fusionauth.client_id', 'foo');
    Config::set('fusionauth.audience', 'bar');
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => 'baz', 'iss' => 'bar']);
})->throws(InvalidTokenException::class);

test('::validate() will not throw anything if everything is good', function () {
    Config::set('fusionauth.audience', 'bar');
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => 'bar', 'iss' => 'foo']);

    // Basic expectation to avoid the warning
    expect(true)->toBeTrue();
});

test('::validate() will not throw anything if audience matches the client_id', function () {
    Config::set('fusionauth.client_id', 'baz');
    Config::set('fusionauth.audience', 'foo');
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => 'baz', 'iss' => 'foo']);

    // Basic expectation to avoid the warning
    expect(true)->toBeTrue();
});

test('::validate() will not throw anything if at least one token audience matches a valid audience as array', function () {
    Config::set('fusionauth.audience', ['foo', 'bar']);
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => ['baz', 'bar'], 'iss' => 'foo']);
    FusionAuthJwt::validate((object) ['aud' => 'bar', 'iss' => 'foo']);

    // Basic expectation to avoid the warning
    expect(true)->toBeTrue();
});


test('::validate() will not throw anything if at least one token audience matches a valid audience as string', function () {
    Config::set('fusionauth.audience', 'bar');
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => ['baz', 'bar'], 'iss' => 'foo']);
    FusionAuthJwt::validate((object) ['aud' => 'bar', 'iss' => 'foo']);

    // Basic expectation to avoid the warning
    expect(true)->toBeTrue();
});

test('::validate() will throw an error if token audience as string does not match a valid audience', function () {
    Config::set('fusionauth.audience', ['foo', 'bar']);
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => 'qux', 'iss' => 'foo']);
})->throws(InvalidTokenException::class);

test('::validate() will throw an error if token audience as array does not match a valid audience as string', function () {
    Config::set('fusionauth.audience', 'foo');
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => ['baz', 'qux'], 'iss' => 'foo']);
})->throws(InvalidTokenException::class);

test('::validate() will throw an error if token audience as array does not match a valid audience as array', function () {
    Config::set('fusionauth.audience', ['foo', 'bar']);
    Config::set('fusionauth.issuers', ['foo', 'bar']);

    FusionAuthJwt::validate((object) ['aud' => ['baz', 'qux'], 'iss' => 'foo']);
})->throws(InvalidTokenException::class);

test('::fetchPublicKeys() returns Key instances, caches raw PEMs, and reuses the cache on subsequent calls', function () {
    Config::set('fusionauth.domain', 'auth.example.test');
    Cache::forget('fusionauth.v3.public_keys');

    $pemA = "-----BEGIN PUBLIC KEY-----\nKEY-A\n-----END PUBLIC KEY-----";
    $pemB = "-----BEGIN PUBLIC KEY-----\nKEY-B\n-----END PUBLIC KEY-----";

    Http::fake([
        'https://auth.example.test/api/jwt/public-key' => Http::response([
            'publicKeys' => [
                'kid-a' => $pemA,
                'kid-b' => $pemB,
            ],
        ]),
    ]);

    $fetch = new ReflectionMethod(FusionAuthJwt::class, 'fetchPublicKeys');

    $keys = $fetch->invoke(null, FusionAuthJwt::ALGO_RS256);

    expect($keys)->toHaveCount(2)
        ->and($keys['kid-a'])->toBeInstanceOf(Key::class)
        ->and($keys['kid-a']->getAlgorithm())->toBe(FusionAuthJwt::ALGO_RS256)
        ->and($keys['kid-a']->getKeyMaterial())->toBe($pemA)
        ->and($keys['kid-b'])->toBeInstanceOf(Key::class)
        ->and($keys['kid-b']->getAlgorithm())->toBe(FusionAuthJwt::ALGO_RS256)
        ->and($keys['kid-b']->getKeyMaterial())->toBe($pemB);

    // The cache must hold raw PEM strings — Key objects are rebuilt per-call
    // so the cached payload survives serialization across requests.
    expect(Cache::get('fusionauth.v3.public_keys'))
        ->toBe(['kid-a' => $pemA, 'kid-b' => $pemB]);

    $keysAgain = $fetch->invoke(null, FusionAuthJwt::ALGO_RS256);

    expect($keysAgain['kid-a'])->toBeInstanceOf(Key::class)
        ->and($keysAgain['kid-a']->getKeyMaterial())->toBe($pemA);

    Http::assertSentCount(1);
});
