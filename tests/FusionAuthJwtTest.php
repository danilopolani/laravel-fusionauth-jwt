<?php

use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenAlgorithmException;
use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenException;
use DaniloPolani\FusionAuthJwt\FusionAuthJwt;
use Illuminate\Support\Facades\Config;

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
