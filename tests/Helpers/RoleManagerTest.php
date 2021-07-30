<?php

use DaniloPolani\FusionAuthJwt\FusionAuthJwtUser;
use DaniloPolani\FusionAuthJwt\Helpers\RoleManager;
use Illuminate\Support\Facades\Auth;

test('::getRoles() empty when not logged in', function () {
    expect(RoleManager::getRoles())->toBe([]);
});

test('::getRoles() with a logged in user', function () {
    Auth::guard('fusionauth')->setUser(
        new FusionAuthJwtUser(['roles' => ['user', 'admin']])
    );

    expect(RoleManager::getRoles())->toBe(['user', 'admin']);
});

test('::hasRole() false when not logged in', function () {
    expect(RoleManager::hasRole('user'))->toBeFalse();
});

test('::hasRole() with a logged in user', function () {
    Auth::guard('fusionauth')->setUser(
        new FusionAuthJwtUser(['roles' => ['user', 'admin']])
    );

    expect(RoleManager::hasRole('user'))->toBeTrue();
    expect(RoleManager::hasRole('foobar'))->toBeFalse();
});
