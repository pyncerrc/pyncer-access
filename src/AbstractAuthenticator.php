<?php
namespace Pyncer\Access;

use Psr\Http\Message\ServerRequestInterface as PsrServerRequestInterface;
use Psr\Log\LoggerAwareInterface as PsrLoggerAwareInterface;
use Psr\Log\LoggerAwareTrait as PsrLoggerAwareTrait;
use Pyncer\Access\AuthenticatorInterface;
use Pyncer\Data\Model\ModelInterface;

use function in_array;

abstract class AbstractAuthenticator implements
    AuthenticatorInterface,
    PsrLoggerAwareInterface
{
    use PsrLoggerAwareTrait;

    protected ?ModelInterface $userModel = null;
    protected ?ModelInterface $guestUserModel = null;
    protected bool $hasAuthenticated = false;

    public function __construct(
        protected PsrServerRequestInterface $request,
        protected string $scheme,
        protected string $realm,
    ) {}

    public function getScheme(): string
    {
        return $this->scheme;
    }

    public function getRealm(): string
    {
        return $this->realm;
    }

    public function getUser(): ?ModelInterface
    {
        return $this->userModel ?? $this->guestUserModel;
    }

    public function getUserId(): ?int
    {
        $userModel = $this->getUser();
        if ($userModel) {
            return $userModel->getId();
        }

        return null;
    }

    public function isUser(): bool
    {
        return ($this->userModel !== null);
    }

    public function isGuest(): bool
    {
        return ($this->userModel === null);
    }

    public function hasAuthenticated(): bool
    {
        return $this->hasAuthenticated;
    }
}
