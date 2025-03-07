<?php

return [

    /*
    |--------------------------------------------------------------------------
    |   Your FusionAuth domain
    |--------------------------------------------------------------------------
    |
    */
    'domain' => env('FUSIONAUTH_DOMAIN'),

    /*
    |--------------------------------------------------------------------------
    |   App Client ID
    |--------------------------------------------------------------------------
    |
    */
    'client_id' => env('FUSIONAUTH_CLIENT_ID'),

    /*
    |--------------------------------------------------------------------------
    |   App Client Secret
    |--------------------------------------------------------------------------
    |
    */
    'client_secret' => env('FUSIONAUTH_CLIENT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    |   Authorized issuers
    |--------------------------------------------------------------------------
    |
    */
    'issuers' => [
        env('FUSIONAUTH_ISSUER'),
    ],

    /*
    |--------------------------------------------------------------------------
    |   Authorized audience
    |--------------------------------------------------------------------------
    |
    */
    'audience' => [
        env('FUSIONAUTH_AUDIENCE'),
    ],

    /*
    |--------------------------------------------------------------------------
    |   Token supported algorithms
    |--------------------------------------------------------------------------
    |
    */
    'supported_algs' => ['RS256'],

    /*
    |--------------------------------------------------------------------------
    |   Default role name
    |--------------------------------------------------------------------------
    |
    | Name of the default role to check when using the CheckRole middleware.
    |
    */
    'default_role' => null,
];
