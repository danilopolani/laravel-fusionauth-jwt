<?php

namespace DaniloPolani\FusionAuthJwt\Helpers;

use Illuminate\Support\Facades\Auth;

class RoleManager
{
    /**
     * Check if current authenticated user has a role.
     *
     * @param  string $role
     * @return bool
     */
    public static function hasRole(string $role): bool
    {
        return in_array($role, self::getRoles());
    }

    /**
     * Get all roles of authenticated user.
     * If guest, an empty array will be returned.
     *
     * @return array
     */
    public static function getRoles(): array
    {
        // @phpstan-ignore-next-line
        return optional(Auth::guard('fusionauth')->user())->roles ?: [];
    }
}
