<?php

namespace DaniloPolani\FusionAuthJwt\Tests;

use DaniloPolani\FusionAuthJwt\FusionAuthJwtServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @return array
     */
    public function getPackageProviders($app)
    {
        return [
            FusionAuthJwtServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function defineEnvironment($app)
    {
        // Setup default database to use sqlite :memory:
        $app['config']->set('auth.guards.fusionauth', [
            'driver' => 'fusionauth',
            'provider' => 'fusionauth',
        ]);
        $app['config']->set('auth.providers.fusionauth', [
           'driver' => 'fusionauth',
        ]);
    }
}
