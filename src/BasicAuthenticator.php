<?php
namespace Pyncer\Access;

use Psr\Http\Message\ServerRequestInterface as PsrServerRequestInterface;
use Pyncer\Access\AbstractBasicAuthenticator;
use Pyncer\Data\Mapper\MapperAdaptorInterface;

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
            if ($this->guestUserId) {
                $this->guestUserModel = $this->userMapperAdaptor->getMapper()->selectById(
                    $this->guestUserId,
                    $this->userMapperAdaptor->getMapperQuery()
                );
            }

            return false;
        }

        $this->userModel = $userModel;

        return true;
    }
}
