<?php
namespace Pyncer\Access;

use Pyncer\Access\AuthenticatorInterface;

interface BasicAuthenticatorInterface extends AuthenticatorInterface
{
    public function authenticate(string $username, string $password): bool;
}
