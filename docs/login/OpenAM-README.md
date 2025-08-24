##Introduction
This document outlines a basic SAML integration between the OpenAM server and the 
Cloud Foundry UAA.

###Step 1

Download and install software

  - a) Download a Tomcat .tar.gz from [http://tomcat.apache.org](http://tomcat.apache.org)
  - b) Download OpenAM WAR file [https://backstage.forgerock.com/#!/downloads/enterprise/OpenAM](https://backstage.forgerock.com/#!/downloads/enterprise/OpenAM) (look for OpenAM 11 non subscription)
  - c) Unzip Apache Tomcat
  - d) Create a directory under `apache-tomcat-7.0.55/webapps/` called 'openam'
  - e) Extract contents (zip) of OpenAM-11.0.0.war into `apache-tomcat-7.0.55/webapps/openam`

###Step 2
Open apache-tomcat-7.0.55/conf/server.xml

  - a) Change the value 8005 to -1 on the line 
    `<Server port="8005" shutdown="SHUTDOWN">`
  - b) Change the value 8080 to 8081 on the line 
    `<Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />`
  - c) Remove the line 
    `<Connector port="8009" protocol="AJP/1.3" redirectPort="8443" />`
  - d) Go to the directory apache-tomcat-7.0.55/bin
  - e) Start Tomcat on port 8081 by typing `./catalina.sh run` (Ctrl+C to kill it)

###Step 3
Initialize OpenAM

  - a) Go to [http://localhost:8081/openam](http://localhost:8081/openam)
  - b) Click 'Create Default Configuration' and set password for amAdmin and UrlAccessAgent
  - c) Click Create
     (this will create the directory ~/openam 
      if you wish to restart an installation, wipe this dir clean and restart tomcat)
  - d) Log in as amAdmin and the password you just created

###Step 4
Setup OpenAM as an Identity Provider (IDP)

  - a) Click "Create Hosted Identity Provider"
  - b) Select 'test' for the signing key
  - c) Type 'circleoftrust' for "New Circle of Trust" (we do not use this value)
  - d) Add an attribute by name `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` and value `mail` (this means the email will become the username)
  - e) Click 'Add' on the attribute
  - f) Click 'Configure'


###Step 5
Configure and start UAA

  - a) Configure login.yml
  - b) uncomment '#providers:' under login.saml
  - c) uncomment the OpenAM section under 'openam-local'
  - d) make sure you have 'spring_profiles: saml'
  - e) Start UAA server on port 8080 (./gradlew run)

        DEBUG --- MetadataManager: Initializing provider data org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider@41f4a18b
        DEBUG --- MetadataManager: Found metadata EntityDescriptor with ID
        DEBUG --- MetadataManager: Remote entity http://localhost:8081/openam available
        DEBUG --- MetadataManager: Metadata provider was initialized org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider@41f4a18b
        DEBUG --- MetadataManager: Reloading metadata was finished

###Step 6
Configure OpenAM to have UAA as a service that wishes to authenticate

  - a) Click 'register a service provider'
  - b) Put the 'http://localhost:8080/uaa/saml/metadata' as the URL
  - c) Click 'Configure'

###Step 7
Create a SAML user

  - a) Click 'Access Control'
  - b) Click '/ (Top Level Realm)'
  - c) Click 'Subjects'
  - d) Click 'New'
    Enter user information — After the user is created, click on it again and give the user an email address
  - e) Log out of OpenAM

###Step 8
Test SAML Authentication

  - a) Go to http://localhost:8080/uaa
  - b) Click "Use your corporate credentials" (or the link name you configured in login.yml)
  - c) Sign in with the user you created
