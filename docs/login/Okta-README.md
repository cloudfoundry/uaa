##Introduction
This document outlines a very simple SAML integration between Okta and the
Cloud Foundry login-server. 
It assumes that you have a SAML application setup on Okta Preview with admin rights to it.

##Pivotal Preview and Standalone Login Server
The login-server comes with with a `sample-okta-metadata.xml` file
that will redirect your SAML request back to http://localhost:8080/login
This configuration requires you to have an account on 
https://pivotal.oktapreview.com

###Step 1
Configure and start the login-server/UAA

   - a) Configure login.yml
   - b) Uncomment the Okta section under '# Local Okta configuration'
   - c) Make sure the spring_profiles is set to 'saml,default,fileMetadata'

           spring_profiles: saml,default,fileMetadata
           login:
             idpEntityAlias: okta-local
             idpMetadataFile: sample-okta-localhost.xml
             saml:
               nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
               assertionConsumerIndex: 0
               signMetaData: true
               signRequest: true

   - d) Start the UAA/Login Server on port 8080 (./gradlew run)

###Step 2
Test SAML authentication

  - a) Go to http://localhost:8080/login
  - b) Click `Use your corporate credentials`
  - c) Authenticate on the Okta server
  - d) You should be redirected to 'localhost:8080/login' and be signed in with your credentials (email address)
  
##Pivotal Preview - Configure Custom Application
To configure a custom redirect URL on the https://pivotal.oktapreview.com 
domain, the steps are outlined.

If you have your own Okta domain setup, follow these steps, and 
replace the Pivotal values with your own.

###Step 1
Download the IDP Metadata

  - a) Go to https://pivotal-admin.oktapreview.com and log in
  - b) Click on 'Admin'
  - c) Click on the 'Applications' tab and go to your SAML application
  - d) Go to the 'Sign On' tab and click on 'Identity Provider Metadata'
  - e) Save this file to a location which can be used in the login server

###Step 2
Configure and start the login-server/UAA

   - a) Configure login.yml
   - b) Uncomment the Okta section under '# Local Okta configuration'
   - c) Set the 'idpMetadataFile' property to the full location of the IDP metadata file (downloaded in Step 1)
   - d) Make sure the spring_profiles is set to 'saml,default,fileMetadata'
   - e) Start the UAA/Login Server on port 8080 (./gradlew run)

###Step 3
Configure Okta to have login-server as a service that wishes to authenticate

  - a) Go to your Okta application and click on the 'General' tab
  - b) Edit the SAML settings
  - c) Fill in the 'SingleSignOnURL' field  with 'http://localhost:8080/login/saml/SSO/alias/okta-local'
       and select 'Use this for Recipient URL and Destination URL'
  - d) Fill in the 'Audience URI' field with 'cloudfoundry-saml-login-local' which is the entityID for the login-server
  - e) Change the 'Request Compression' to Uncompressed
  - f) Click Next and then Finish

###Step 4
Test SAML authentication

  - a) Go to 'My Applications' on Octa Preview
  - b) Click on your SAML application
  - c) You should be redirected to 'localhost:8080/login' and be signed in with your credentials



