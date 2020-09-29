<?php
namespace App\Security;

use App\Repository\UserRepository;
use App\Controller\SecurityController;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;


class LoginFormAuthenticator extends AbstractAuthenticator
{
    private $userRepository; 
    private $em;
    private $urlgenerator;
    public function __construct(UserRepository $userRepository, 
    EntityManagerInterface $em,
    UrlGeneratorInterface $urlgenerator)
    {
        $this->userRepository = $userRepository;
        $this->em = $em;
        $this->urlgenerator = $urlgenerator;
    }
    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'app_login' && 
        $request->isMethod('POST') ;
    }

    /**
     * Create a passport for the current request.
     *
     * The passport contains the user, credentials and any additional information
     * that has to be checked by the Symfony Security system. For example, a login
     * form authenticator will probably return a passport containing the user, the
     * presented password and the CSRF token value.
     *
     * You may throw any AuthenticationException in this method in case of error (e.g.
     * a UsernameNotFoundException when the user cannot be found).
     *
     * @throws AuthenticationException
     */
    public function authenticate(Request $request): PassportInterface
    {
        $email = $request->request->get('email');
        $user = $this->userRepository->findOneByEmail($email);

        $request->getSession()->set(
            SecurityController::OLD_EMAIL, $email
        );

        if (!$user) {
            throw new CustomUserMessageAuthenticationException();
        }
        return new Passport($user, new PasswordCredentials($request->request->get('password')),[
            new CsrfTokenBadge('token', $request->request->get('csrf_token')),
            new RememberMeBadge
            // new PasswordUpgradeBadge($request->get('password'), $this->userRepository)
        ]);
    }

    /**
     * Called when authentication executed and was successful!
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the last page they visited.
     *
     * If you return null, the current request will continue, and the user
     * will be authenticated. This makes sense, for example, with an API.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $request->getSession()->getFlashBag()->add('success', 'Login ok');
        return new RedirectResponse($this->urlgenerator->generate('app_home'));
    }

    /**
     * Called when authentication executed, but failed (e.g. wrong username password).
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the login page or a 403 response.
     *
     * If you return null, the request will continue, but the user will
     * not be authenticated. This is probably not what you want to do.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->getFlashBag()->add('danger', 'Invalide login');
        
        return new RedirectResponse($this->urlgenerator->generate('app_login'));
    }

}