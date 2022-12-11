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
    ) {
        parent::__construct($request, $realm);
    }

    protected function authenticate(string $username, string $password): bool
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
