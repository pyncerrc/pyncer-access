<?php
namespace Pyncer\Access;

use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequestInterface;
use Pyncer\Access\AbstractAuthenticator;
use Pyncer\Access\BasicAuthenticatorInterface;
use Pyncer\Data\Model\ModelInterface;
use Pyncer\Http\Message\Response;
use Pyncer\Http\Message\Status;
use Pyncer\Http\Server\RequestHandlerInterface;

use function base64_encode;
use function count;
use function explode;

use const Pyncer\ENCODING as PYNCER_ENCODING;

abstract class AbstractBasicAuthenticator extends AbstractAuthenticator implements
    BasicAuthenticatorInterface
{
    public function __construct(
        PsrServerRequestInterface $request,
        string $realm,
    ) {
        parent::__construct($request, 'Basic', $realm);
    }

    public function getResponse(
        RequestHandlerInterface $handler
    ): ?PsrResponseInterface
    {
        $header = $this->request->getHeader('Authorization');

        if (!$header) {
            return null;
        }

        $credentials = explode(' ', $header[0], 2);

        if (count($credentials) !== 2 ||
            $credentials[0] !== $this->getScheme()
        ) {
            return $this->getChallengeResponse(
                Status::CLIENT_ERROR_400_BAD_REQUEST
            );
        }

        $credentials = base64_decode($credentials[1]);
        $credentials = explode(':', $credentials);

        if (count($credentials) !== 2) {
            return $this->getChallengeResponse(
                Status::CLIENT_ERROR_400_BAD_REQUEST
            );
        }

        if (!$this->authenticate($credentials[0], $credentials[1])) {
            return $this->getChallengeResponse(
                Status::CLIENT_ERROR_401_UNAUTHORIZED
            );
        }

        $this->hasAuthenticated = true;

        return null;
    }

    public function getChallengeResponse(
        Status $status,
        array $params = [],
    ): PsrResponseInterface
    {
        return new Response(
            status: $status,
            headers: [
                'WWW-Authenticate' =>
                    'Basic ' .
                    'realm="' . $this->getRealm() . '", ' .
                    'charset="' . PYNCER_ENCODING . '"'
            ]
        );
    }
}
