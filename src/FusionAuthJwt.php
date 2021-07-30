<?php

namespace DaniloPolani\FusionAuthJwt;

use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenAlgorithmException;
use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenException;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class FusionAuthJwt
{
    /**
     * Default length of cache persistence. Defaults to 10 minutes.
     *
     * @see https://www.php-fig.org/psr/psr-16/#12-definitions
     */
    public const JWKS_CACHE_TTL = 600;

    public const ALGO_RS256 = 'RS256';

    public const ALGO_HS256 = 'HS256';

    /**
     * Decode a JWT.
     *
     * @throws InvalidTokenAlgorithmException             Provided algorithm is not supported
     * @throws InvalidTokenException                      Decoded JWT iss or aud are invalid
     *
     * @throws \InvalidArgumentException                  Provided JWT was empty
     * @throws \UnexpectedValueException                  Provided JWT was invalid
     * @throws \Firebase\JWT\SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws \Firebase\JWT\BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws \Firebase\JWT\BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws \Firebase\JWT\ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @param  string $jwt
     * @return array
     */
    public static function decode(string $jwt): array
    {
        $supportedAlgs = Config::get('fusionauth.supported_algs');

        if (!in_array($supportedAlgs[0] ?? null, [self::ALGO_RS256, self::ALGO_HS256])) {
            throw new InvalidTokenAlgorithmException('Unsupported token signing algorithm configured. Must be either RS256 or HS256.');
        }

        if ($supportedAlgs[0] === self::ALGO_RS256) {
            $data = JWT::decode($jwt, self::fetchPublicKeys(), $supportedAlgs);
        } else {
            $data = JWT::decode($jwt, Config::get('fusionauth.client_secret'), $supportedAlgs);
        }

        self::validate($data);

        return (array) $data;
    }

    /**
     * Validate a token by its aud and iss.
     *
     * @throws InvalidTokenException
     *
     * @param  object $token
     * @return void
     */
    public static function validate(object $token): void
    {
        if (!in_array($token->iss, Config::get('fusionauth.issuers'))) {
            throw new InvalidTokenException('Issuer "' . $token->iss . '" is not authorized.');
        }

        $possibleAudiences = [
            // Fallback to client_id to avoid "null $token->aud" matching "null fusionauth.audience"
            Config::get('fusionauth.audience', Config::get('fusionauth.client_id')),
            Config::get('fusionauth.client_id'),
        ];

        // Validate aud against the audience and client id (may be a token from client_credentials)
        if (!in_array($token->aud, $possibleAudiences)) {
            throw new InvalidTokenException('Audience "' . $token->aud . '" is not authorized.');
        }
    }

    /**
     * Fetch public keys generated from JWKS.
     *
     * @return array
     */
    protected static function fetchPublicKeys(): array
    {
        return Cache::remember(
            'fusionauth.public_keys',
            self::JWKS_CACHE_TTL,
            fn () => Http::get('https://' . Config::get('fusionauth.domain') . '/api/jwt/public-key')
                ->throw()
                ->json('publicKeys', [])
        );
    }
}
