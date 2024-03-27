<?php
namespace Pyncer\Access;

use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequestInterface;
use Pyncer\Access\AbstractBearerAuthenticator;
use Pyncer\Data\Mapper\MapperAdaptorInterface;
use Pyncer\Http\Server\RequestHandlerInterface;

use const Pyncer\DATE_TIME_NOW as PYNCER_DATE_TIME_NOW;

class BearerAuthenticator extends AbstractBearerAuthenticator
{
    public function __construct(
        protected MapperAdaptorInterface $tokenMapperAdaptor,
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

    public function authenticate(string $token): bool
    {
        $tokenModel = $this->tokenMapperAdaptor->getMapper()->selectByColumns(
            $this->tokenMapperAdaptor->getFormatter()->formatData([
                'scheme' => $this->getScheme(),
                'realm' => $this->getRealm(),
                'token' => $token,
            ]),
            $this->tokenMapperAdaptor->getMapperQuery()
        );

        if (!$tokenModel) {
            return false;
        }

        $this->tokenModel = $tokenModel;

        $token = $this->tokenMapperAdaptor->getFormatter()->unformatData(
            $tokenModel->getData()
        );

        if ($token['expiration_date_time'] ?? null) {
            if ($token['expiration_date_time'] < PYNCER_DATE_TIME_NOW) {
                return false;
            }
        }

        if (!($token['user_id'] ?? null)) {
            return true;
        }

        $userModel = $this->userMapperAdaptor->getMapper()->selectById(
            $token['user_id'],
            $this->userMapperAdaptor->getMapperQuery()
        );

        if (!$userModel) {
            return false;
        }

        $this->userModel = $userModel;

        return true;
    }

}
