<?php

namespace DaniloPolani\FusionAuthJwt\Http\Middleware;

use DaniloPolani\FusionAuthJwt\Helpers\RoleManager;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class CheckRole
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null $role
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ?string $role = null)
    {
        /** @var \App\FusionAuth\FusionAuthUser $user */
        if (!Auth::guard('fusionauth')->check()) {
            throw new UnauthorizedHttpException('Bearer');
        }

        $finalRole = $role ?: Config::get('fusionauth.default_role');

        if (is_null($finalRole) || !RoleManager::hasRole($finalRole)) {
            throw new UnauthorizedHttpException('Bearer role="' . $role . '"');
        }

        return $next($request);
    }
}
