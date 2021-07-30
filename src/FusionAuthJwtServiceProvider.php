<?php

namespace DaniloPolani\FusionAuthJwt;

use DaniloPolani\FusionAuthJwt\Http\Middleware\CheckRole;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class FusionAuthJwtServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Automatically apply the package configuration
        $this->mergeConfigFrom(__DIR__.'/../config/fusionauth.php', 'fusionauth');
    }

    public function boot()
    {
        Auth::provider(
            'fusionauth',
            fn (Application $app) => $app->make(FusionAuthJwtUserProvider::class)
        );

        Auth::extend(
            'fusionauth',
            fn (Application $app, string $name, array $config) => new RequestGuard(
                fn (Request $request, FusionAuthJwtUserProvider $provider) => $provider->retrieveByCredentials([
                    'jwt' => $request->bearerToken(),
                ]),
                $app['request'],
                $app['auth']->createUserProvider($config['provider'])
            )
        );

        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('fusionauth.role', CheckRole::class);

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/fusionauth.php' => config_path('fusionauth.php'),
            ], 'fusionauth-jwt-config');
        }
    }
}
