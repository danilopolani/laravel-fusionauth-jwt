<?php

use DaniloPolani\FusionAuthJwt\FusionAuthJwtUser;
use DaniloPolani\FusionAuthJwt\Http\Middleware\CheckRole;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;

use function PHPUnit\Framework\assertTrue;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

beforeEach(function () {
    Config::set('fusionauth.default_role', 'user');

    $this->request = new Request();
    $this->nullFn = fn () => assertTrue(true);
});

test('block if guest', function () {
    (new CheckRole())->handle($this->request, $this->nullFn);
})->throws(UnauthorizedHttpException::class);

test('block if no role specified', function () {
    Auth::guard('fusionauth')->setUser(new FusionAuthJwtUser([]));

    (new CheckRole())->handle($this->request, $this->nullFn);
})->throws(UnauthorizedHttpException::class);

test('block if user has not the default role', function () {
    Auth::guard('fusionauth')->setUser(
        new FusionAuthJwtUser(['roles' => ['foo']])
    );

    (new CheckRole())->handle($this->request, $this->nullFn);
})->throws(UnauthorizedHttpException::class);

test('block if user has not the custom role provided', function () {
    Auth::guard('fusionauth')->setUser(
        new FusionAuthJwtUser(['roles' => ['user']])
    );

    (new CheckRole())->handle($this->request, $this->nullFn, 'admin');
})->throws(UnauthorizedHttpException::class);

test('handles default role for a user', function () {
    Auth::guard('fusionauth')->setUser(
        new FusionAuthJwtUser(['roles' => ['user']])
    );

    (new CheckRole())->handle($this->request, $this->nullFn);
});

test('handles a custom role', function () {
    Auth::guard('fusionauth')->setUser(
        new FusionAuthJwtUser(['roles' => ['user', 'admin']])
    );

    (new CheckRole())->handle($this->request, $this->nullFn, 'admin');
});
