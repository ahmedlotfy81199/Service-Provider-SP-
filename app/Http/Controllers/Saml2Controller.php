<?php

namespace App\Http\Controllers;

use OneLogin\Saml2\Auth as Saml2Auth;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use App\Models\User;

class Saml2Controller extends Controller
{
    protected $saml2Auth;

    public function __construct()
    {
        $this->saml2Auth = new Saml2Auth(config('saml2_settings'));
    }

    public function metadata()
    {
        $settings = $this->saml2Auth->getSettings();
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);
        if (!empty($errors)) {
            throw new \OneLogin\Saml2\Error(
                'Invalid SP metadata: ' . implode(', ', $errors),
                \OneLogin\Saml2\Error::METADATA_SP_INVALID
            );
        }
        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    public function acs(Request $request)
    {
    
        // Process the SAML response
        $this->saml2Auth->processResponse();

        // Check for errors
        $errors = $this->saml2Auth->getErrors();
        dd($errors);
        if (!empty($errors)) {
            throw new \OneLogin\Saml2\Error(
                'SAML ACS Error: ' . implode(', ', $errors),
                \OneLogin\Saml2\Error::METADATA_SP_INVALID
            );
        }

        // Get the attributes from the SAML response
        $userData = $this->saml2Auth->getAttributes();
        // Assuming the email attribute is used for authentication
        if (!isset($userData['email'][0])) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email attribute not found in SAML response'
            ], 500);
        }
        dd($userData);
        $userEmail = $userData['email'][0];

        // Authenticate or create the user
        $user = User::firstOrCreate(['email' => $userEmail], [
            'name' => $userData['name'][0] ?? $userEmail,
            // Add other user details as necessary
        ]);

        // Log the user in
        Auth::login($user);

        // Redirect to the intended URL or a default page
        return redirect()->intended('/');
    }


    public function sls()
    {
        $this->saml2Auth->processSLO();
        Auth::logout();
        return redirect('/');
    }

    public function login()
    {
        // Redirect to IdP SSO URL
        return $this->saml2Auth->login(env('SAML2_SP_ACS_URL'));
    }
}
