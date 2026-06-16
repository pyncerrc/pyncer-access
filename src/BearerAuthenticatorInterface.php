<?php
namespace Pyncer\Access;

use Pyncer\Access\AuthenticatorInterface;
use Pyncer\Data\Model\ModelInterface;

interface BearerAuthenticatorInterface extends AuthenticatorInterface
{
    public function getToken(): ?ModelInterface
    public function authenticate(string $token): bool;
}
