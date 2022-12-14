<?php
namespace Pyncer\Access;

use Pyncer\Access\AuthenticatorInterface;

interface BearerAuthenticatorInterface extends AuthenticatorInterface
{
    public function authenticate(string $token): bool;
}
