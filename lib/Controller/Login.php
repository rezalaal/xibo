<?php
/*
 * Xibo - Digital Signage - http://www.xibo.org.uk
 * Copyright (C) 2006-2015 Daniel Garner
 *
 * This file (Login.php) is part of Xibo.
 *
 * Xibo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Xibo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Xibo.  If not, see <http://www.gnu.org/licenses/>.
 */
namespace Xibo\Controller;
use Xibo\Entity\User;
use Xibo\Exception\AccessDeniedException;
use Xibo\Exception\NotFoundException;
use Xibo\Factory\UserFactory;
use Xibo\Helper\Session;
use Xibo\Service\ConfigServiceInterface;
use Xibo\Service\DateServiceInterface;
use Xibo\Service\LogServiceInterface;
use Xibo\Service\SanitizerServiceInterface;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/**
 * Class Login
 * @package Xibo\Controller
 */
class Login extends Base
{
    /**
     * @var Session
     */
    private $session;

    /**
     * @var UserFactory
     */
    private $userFactory;

    /**
     * Set common dependencies.
     * @param LogServiceInterface $log
     * @param SanitizerServiceInterface $sanitizerService
     * @param \Xibo\Helper\ApplicationState $state
     * @param User $user
     * @param \Xibo\Service\HelpServiceInterface $help
     * @param DateServiceInterface $date
     * @param ConfigServiceInterface $config
     * @param Session $session
     * @param UserFactory $userFactory
     */
    public function __construct($log, $sanitizerService, $state, $user, $help, $date, $config, $session, $userFactory)
    {
        $this->setCommonDependencies($log, $sanitizerService, $state, $user, $help, $date, $config);

        $this->session = $session;
        $this->userFactory = $userFactory;
    }

    /**
     * Output a login form
     */
    public function loginForm()
    {
        $this->getLog()->debug($this->getApp()->flashData());
        // Template
        $this->getState()->template = 'login';
        $this->getState()->setData(['version' => VERSION]);
    }

    /**
     * login
     */
    public function login()
    {
        // Capture the prior route (if there is one)
        $redirect = 'login';
        $priorRoute = ($this->getSanitizer()->getString('priorRoute'));

        try {
            // Get our username and password
            $username = $this->getSanitizer()->getUserName('username');
            $password = $this->getSanitizer()->getPassword('password');

            $this->getLog()->debug('Login with username %s', $username);

            // Get our user
            try {
                /* @var User $user */
                $user = $this->userFactory->getByName($username);

                // Check password
                $user->checkPassword($password);

                $user->touch();

                $this->getLog()->info('%s user logged in.', $user->userName);

                // Set the userId on the log object
                $this->getLog()->setUserId($user->userId);

                // Overwrite our stored user with this new object.
                $this->getApp()->user = $user;

                // Switch Session ID's
                $session = $this->session;
                $session->setIsExpired(0);
                $session->regenerateSessionId();
                $session->setUser($user->userId);

                // Audit Log
                $this->getLog()->audit('User', $user->userId, 'Login Granted', [
                    'IPAddress' => $this->getApp()->request()->getIp(),
                    'UserAgent' => $this->getApp()->request()->getUserAgent()
                ]);
            }
            catch (NotFoundException $e) {
                throw new AccessDeniedException('User not found');
            }

            $redirect = ($priorRoute == '' || $priorRoute == '/' || stripos($priorRoute, $this->getApp()->urlFor('login'))) ? $this->getApp()->urlFor('home') : $priorRoute;
        }
        catch (\Xibo\Exception\AccessDeniedException $e) {
            $this->getLog()->warning($e->getMessage());
            $this->getApp()->flash('login_message', __('Username or Password incorrect'));
            $this->getApp()->flash('priorRoute', $priorRoute);
        }
        catch (\Xibo\Exception\FormExpiredException $e) {
            $this->getApp()->flash('priorRoute', $priorRoute);
        }

        $this->setNoOutput(true);
        $this->getLog()->debug('Redirect to %s', $redirect);
        $this->getApp()->redirect($redirect);
    }

    /**
     * Log out
     * @param bool $redirect
     */
    public function logout($redirect = true)
    {
        $this->getUser()->touch();

        // to log out a user we need only to clear out some session vars
        unset($_SESSION['userid']);
        unset($_SESSION['username']);
        unset($_SESSION['password']);

        $session = $this->session;
        $session->setIsExpired(1);

        if ($redirect)
            $this->getApp()->redirectTo('login');
    }

    /**
     * Ping Pong
     */
    public function PingPong()
    {
        $this->session->refreshExpiry = ($this->getSanitizer()->getCheckbox('refreshSession') == 1);
        $this->getState()->success = true;
    }

    /**
     * Shows information about Xibo
     *
     * @SWG\Get(
     *  path="/about",
     *  operationId="about",
     *  tags={"misc"},
     *  summary="About",
     *  description="Information about this API, such as Version code, etc",
     *  @SWG\Response(
     *      response=200,
     *      description="successful response",
     *      @SWG\Schema(
     *          type="object",
     *          additionalProperties={
     *              "title"="version",
     *              "type"="string"
     *          }
     *      )
     *  )
     * )
     */
    function about()
    {
        $response = $this->getState();

        if ($this->getApp()->request()->isAjax()) {
            $response->template = 'about-text';
        }
        else {
            $response->template = 'about-page';
        }

        $response->setData(['version' => VERSION, 'sourceUrl' => $this->getConfig()->getThemeConfig('cms_source_url')]);
    }

    public function forgotPasswordForm()    
    {
        
        $response = $this->getState();

        $response->template = 'forgot-password';

        $this->getState()->setData(['version' => VERSION]);
    }


    public function forgotPassword()
    {
        // Get email
        $email = $this->getSanitizer()->getString('email');
        // Validate email 
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->getApp()->flash('forgot_password_message', __('Enter your email address please.'));
            $this->getApp()->redirect('forgot-password');
        }

        $user = $this->userFactory->getByEmail($email);
        $code = $user->updateResetPasswordCode();
        
        try {
            $this->mailResetPasswordCode($user, $code);
        }catch(\Exception $e)
        {
            $e->getMessage();
        }

        $_SESSION['forgot-password-token'] = hash('sha256', $email);

        $this->getApp()->flash('login_message', __('Check your email to change password'));
        $this->getApp()->redirect('get-reset-code');
    }

    public function mailResetPasswordCode($email, $code)
    {
        // Create a new PHPMailer object
        $mail = new PHPMailer(true);

        $mail->From = $this->getConfig()->getSetting('mail_from');
        $mail->Subject = 'Recovery password';
        $mail->Body    = 'Your recovery password is: '. $code;
        $mail->addAddress($user->email, $user->lastname);
        try {                       
            $mail->send();
        } catch (Exception $e) {
            echo 'Message could not be sent. Error: '. $e->getMessage();
        }
    }

    public function getResetPasswordCodeForm()
    {
        $token = $_SESSION['forgot-password-token'];
        $response = $this->getState();

        $response->template = 'reset-password-code';

        $this->getState()->setData([
            'version' => VERSION,
            'token' => $token
        ]);
    }

    public function resetPassword()
    {
        $code = $this->getSanitizer()->getString('code');
        $token = $this->getSanitizer()->getString('token');
        $password = $this->getSanitizer()->getString('password');
        $confirmPassword = $this->getSanitizer()->getString('confirm-password');
        
        if ($password != $confirmPassword) {
            $this->getApp()->flash('reset_password_message', __('Passwords do not match'));
            $this->getApp()->redirect('get-reset-code');            
        }

        $user = $this->userFactory->check($code, $token);

        if(!$user) {
            $this->getApp()->flash('reset_password_message', __('Invalid code or token'));
            $this->getApp()->redirect('get-reset-code');
        }
        
        $user->passwordRecovery($password, $user->UserID);

        $this->getApp()->flash('login_message', __('Your password has been changed'));
        $this->getApp()->redirect('login');
    }

}
