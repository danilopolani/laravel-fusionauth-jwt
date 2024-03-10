<?php

namespace DaniloPolani\FusionAuthJwt;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * @property-read string $applicationId
 * @property-read string $authenticationType
 * @property-read string $aud
 * @property-read string $iss
 * @property-read string $sub
 * @property-read string $jti
 * @property-read string $scope
 * @property-read string $email
 * @property-read bool $email_verified
 * @property-read array<string> $roles
 * @property-read int $exp
 * @property-read int $iat
 */
class FusionAuthJwtUser implements Authenticatable
{
    private array $userInfo;

    /**
     * FusionAuthUser constructor.
     *
     * @param array $userInfo
     */
    public function __construct(array $userInfo)
    {
        $this->userInfo = $userInfo;
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthIdentifierName()
    {
        return $this->userInfo['sub'];
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthIdentifier()
    {
        return $this->userInfo['sub'];
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthPassword()
    {
        return '';
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthPasswordName()
    {
        return '';
    }

    /**
     * {@inheritDoc}
     */
    public function getRememberToken()
    {
        return '';
    }

    /**
     * {@inheritDoc}
     */
    public function setRememberToken($value)
    {
        //
    }

    /**
     * {@inheritDoc}
     */
    public function getRememberTokenName()
    {
        return '';
    }

    /**
     * Get the whole user info array.
     *
     * @return array
     */
    public function getUserInfo(): array
    {
        return $this->userInfo;
    }

    /**
     * Add a generic getter to get all the properties of the userInfo.
     *
     * @param  string $name
     * @return mixed the related value or null if not found
     */
    public function __get($name)
    {
        return $this->userInfo[$name] ?? null;
    }

    /**
     * Stringify the current user.
     *
     * @return string
     */
    public function __toString()
    {
        return json_encode($this->userInfo);
    }
}
