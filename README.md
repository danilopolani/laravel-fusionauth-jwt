# Laravel FusionAuth JWT

[![Latest Version on Packagist](https://img.shields.io/packagist/v/danilopolani/laravel-fusionauth-jwt.svg?style=flat-square)](https://packagist.org/packages/danilopolani/laravel-fusionauth-jwt)
[![Total Downloads](https://img.shields.io/packagist/dt/danilopolani/laravel-fusionauth-jwt.svg?style=flat-square)](https://packagist.org/packages/danilopolani/laravel-fusionauth-jwt)
![GitHub Actions](https://github.com/danilopolani/laravel-fusionauth-jwt/actions/workflows/main.yml/badge.svg)

Implement an Auth guard for FusionAuth JWTs in Laravel.  
It ships with also a middleware to check against the user role.  

## Installation

You can install the package via composer:

```bash
composer require danilopolani/laravel-fusionauth-jwt
```

Then publish its config file:

```bash
php artisan vendor:publish --tag=fusionauth-jwt-config
```

## Configuration

There are a few notable configuration options for the package.

Key | Type | Description
------------ | ------------- | -------------
`domain` | String | Your FusionAuth domain, e.g. `auth.myapp.com` or `sandbox.fusionauth.io`.
`client_id` | String | The Client ID of the current application.
`client_secret` | String | The Client Secret of the current application.
`issuers` | Array | A list of authorized issuers for the incoming JWT.
`audience` | String \| Null | The ID/Name of the authorized audience. If null, the **Client ID** will be used.
`supported_algs` | Array | The supported algorithms of the JWT. Supported: `RS256` and `HS256`.
`default_role` | String \| Null | The default role to be checked if you're using the [`CheckRole`](#role-middleware) middleware.

## Usage

To start protecting your APIs you need to add the Guard and the Auth Provider to your `config/auth.php` configuration file:

```php
'guards' => [
    // ...
    'fusionauth' => [
        'driver' => 'fusionauth',
        'provider' => 'fusionauth',
    ],
],

'providers' => [
    // ...
    'fusionauth' => [
        'driver' => 'fusionauth',
    ],
],
```

Then you can use the `auth:fusionauth` guard to protect your endpoints; you can apply it to a group or a single route:

```php
// app\Http\Kernel.php

protected $middlewareGroups = [
    'api' => [
        'auth:fusionauth',
        // ...
    ],
];

// or routes/api.php

Route::get('users', [UserController::class, 'index'])
    ->middleware('auth:fusionauth');
```

Now requests for those endpoints will check if the given JWT (given as **Bearer token**) is valid.

To retrieve the current logged in user - or to check if it's logged in - you can use the usual `Auth` facade methods, specifying the `fusionauth` guard:

```php
Auth::guard('fusionauth')->check();

/** @var \DaniloPolani\FusionAuthJwt\FusionAuthJwtUser $user */
$user = Auth::guard('fusionauth')->user();
```

### Role middleware

The package ships with a handy middleware to check for user role (stored in the `roles` key).

You can apply it on a middleware group inside the `Kernel.php` or to specific routes:

```php
// app\Http\Kernel.php

protected $middlewareGroups = [
    'api' => [
        'auth:fusionauth',
        \DaniloPolani\FusionAuthJwt\Http\Middleware\CheckRole::class,
        // ...
    ],
];

// or routes/api.php

Route::get('users', [UserController::class, 'index'])
    ->middleware(['auth:fusionauth', 'fusionauth.role']);
```

By default the middleware will check that the current user has the `default_role` specified in the configuration file, but you can use as well a specific role, different from the default:

```php
// routes/api.php

Route::get('users', [UserController::class, 'index'])
    ->middleware(['auth:fusionauth', 'fusionauth.role:admin']);
```

For more complex cases we suggest you to take a look on how the [`CheckRole`](https://github.com/danilopolani/laravel-fusionauth-jwt/blob/master/src/Http/Middleware/CheckRole.php) middleware is written (using the [`RoleManager`](https://github.com/danilopolani/laravel-fusionauth-jwt/blob/master/src/Helpers/RoleManager.php) class) and write your own.

### Usage in tests

When you need to test your endpoints in Laravel, you can take advantage of the [`actingAs`](https://laravel.com/docs/8.x/http-tests#session-and-authentication) method to set the current logged in user.

You can pass any property you want to the `FusionAuthJwtUser` class, like `email`, `user` etc. Take a look at this example where we specify the user roles:

```php
use DaniloPolani\FusionAuthJwt\FusionAuthJwtUser;

$this
    ->actingAs(
        new FusionAuthJwtUser([
            'roles' => ['user', 'admin'],
        ]),
        'fusionauth',
    )
    ->get('/api/users')
    ->assertOk();
```

If you need to set the authenticated user outside HTTP testing (therefore you can't use `actingAs()`), you can use the `setUser()` method of the `Auth` facade:

```php
use DaniloPolani\FusionAuthJwt\FusionAuthJwtUser;
use Illuminate\Support\Facades\Auth;

Auth::guard('fusionauth')->setUser(
    new FusionAuthJwtUser([
        'roles' => ['user', 'admin'],
    ])
);
```

### Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

### Security

If you discover any security related issues, please email danilo.polani@gmail.com instead of using the issue tracker.

## Credits

-   [Danilo Polani](https://github.com/danilopolani)
-   [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

## Laravel Package Boilerplate

This package was generated using the [Laravel Package Boilerplate](https://laravelpackageboilerplate.com).
