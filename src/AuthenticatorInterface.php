<?php
namespace Pyncer\Access;

use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Pyncer\Data\Model\ModelInterface;
use Pyncer\Http\Message\Status;
use Pyncer\Http\Server\RequestResponseInterface;

interface AuthenticatorInterface extends RequestResponseInterface
{
    public function getScheme(): string;
    public function getRealm(): string;
    public function getUser(): ?ModelInterface;
    public function getUserId(): ?int;
    public function isUser(): bool;
    public function isGuest(): bool;
    public function hasAuthenticated(): bool;

    public function getChallengeResponse(
        Status $status,
        array $params = [],
    ): PsrResponseInterface;
}
