<?php
namespace Pyncer\Access;

use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequestInterface;
use Pyncer\Access\AbstractBasicAuthenticator;
use Pyncer\Data\Mapper\MapperAdaptorInterface;
use Pyncer\Http\Server\RequestHandlerInterface;

class BasicAuthenticator extends AbstractBasicAuthenticator
{
    public function __construct(
        protected MapperAdaptorInterface $userMapperAdaptor,
        PsrServerRequestInterface $request,
        string $realm,
        protected ?int $guestUserId = null,
    ) {
        parent::__construct($request, $realm);
    }

    public function getGuestUserId(): ?int
    {
        return $this->guestUserId;
    }

    public function getResponse(
        RequestHandlerInterface $handler
    ): ?PsrResponseInterface
    {
        $response = parent::getResponse($handler);

        // Set guest model if no user model
        if ($this->userModel === null && $this->guestUserId !== null) {
            $this->guestUserModel = $this->userMapperAdaptor->getMapper()->selectById(
                $this->guestUserId,
                $this->userMapperAdaptor->getMapperQuery()
            );
        }

        return $response;
    }

    public function authenticate(string $username, string $password): bool
    {
        $userModel = $this->userMapperAdaptor->getMapper()->selectByColumns(
            $this->userMapperAdaptor->getFormatter()->formatData([
                'username' => $username,
                'password' => $password,
            ]),
            $this->userMapperAdaptor->getMapperQuery()
        );

        if (!$userModel) {
            return false;
        }

        $this->userModel = $userModel;

        return true;
    }
}
