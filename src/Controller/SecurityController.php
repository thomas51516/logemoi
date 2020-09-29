<?php

namespace App\Controller;

use App\Form\UserRegistrationFormType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class SecurityController extends AbstractController
{
    public const OLD_EMAIL = 'app_logged_user';
    /**
     * @Route("/login", name="app_login")
     */
    public function login()
    {
        return $this->render('security/login.html.twig', [
            'controller_name' => 'SecurityController',
        ]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \LogicException('Erreur inentendue');
    }

    /**
     * @Route("/regiester", name="app_register")
     */
    public function regiester(Request $request, 
    UserPasswordEncoderInterface $passwordEncoder,
    EntityManagerInterface $em):Response
    {
        $form = $this->createForm(UserRegistrationFormType::class);
        $form->handleRequest($request);
        if ( $form->isSubmitted() && $form->isValid()) {
            $user = $form->getData();
            $plainPassword = $form->get('PlainPassword')->getData();
            $password = $passwordEncoder->encodePassword($user, $plainPassword);
            $user->setPassword($password);
            $em->persist($user);
            $em->flush();

            $request->getSession()->getFlashBag()->add('success', 'Registration ok');
            return $this->redirectToRoute('app_home');
        }
        return $this->render(
            'security/register.html.twig',
            ['registration_form'=>$form->createView()]);
    }
}
