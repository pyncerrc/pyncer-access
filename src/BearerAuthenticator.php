<?php
namespace Pyncer\Auth;

use Psr\Http\Message\ServerRequestInterface as PsrServerRequestInterface;
use Pyncer\Auth\AbstractBearerAuthenticator;
use Pyncer\Data\Mapper\MapperAdaptorInterface;

class BearerAuthenticator extends AbstractBearerAuthenticator
{
    public function __construct(
        protected MapperAdaptorInterface $tokenMapperAdaptor,
        protected MapperAdaptorInterface $userMapperAdaptor,
        PsrServerRequestInterface $request,
        string $realm,
    ) {
        parent::__construct($request, $realm);
    }

    protected function authenticate(string $token): bool
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

        $token = $this->tokenMapperAdaptor->getFormatter()->unformatData(
            $tokenModel->getData()
        );

        if (!$token['user_id'] ?? null) {
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
