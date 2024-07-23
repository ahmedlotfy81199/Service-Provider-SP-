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
        $samlResponse = $_POST['SAMLResponse']; // Or however you receive the SAML response
        $decodedResponse = base64_decode($samlResponse); // Decode the base64 encoded SAML Response
      
        $dom = new \DOMDocument();
        $dom->loadXML($decodedResponse);

        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

        // Extract assertions
        $assertions = $xpath->query('//saml:Assertion');

        // Loop through each assertion
        foreach ($assertions as $assertion) {
            // Extract NameID
            $nameID = $xpath->query('saml:Subject/saml:NameID', $assertion);
            $email = isset($nameID[0]) ? $nameID[0]->textContent : null;

            // Extract Attributes
            $attributes = $xpath->query('saml:AttributeStatement/saml:Attribute', $assertion);
            foreach ($attributes as $attribute) {
                $attributeName = $attribute->getAttribute('Name');
                $attributeValues = $xpath->query('saml:AttributeValue', $attribute);
                foreach ($attributeValues as $value) {
                    echo "Attribute Name: " . $attributeName . "\n";
                    echo "Attribute Value: " . $value->textContent . "\n";
                }
            }

            echo "Email: " . $email . "\n";
        }

        // Extract Response details
        $response = $xpath->query('//samlp:Response');
        if ($response->length > 0) {
            $issuer = $xpath->query('samlp:Issuer', $response[0]);
            echo "Issuer: " . (isset($issuer[0]) ? $issuer[0]->textContent : 'Unknown') . "\n";

            $statusCode = $xpath->query('samlp:Status/samlp:StatusCode', $response[0]);
            echo "Status Code: " . (isset($statusCode[0]) ? $statusCode[0]->getAttribute('Value') : 'Unknown') . "\n";
        }
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
