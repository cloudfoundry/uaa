## The Cloud Foundry SAML Login Server

The saml_login server supports two additional features on top of what you get from the regular [login-server] [1]. 
It adds authentication using an external SAML source. We have tested our authentication with 
[OpenAM] [2] and the vCenter SSO appliance. 

  [1]: https://github.com/cloudfoundry/login-server/tree/master "login-server"
  [2]: https://github.com/cloudfoundry/login-server/tree/master/OpenAM-README.md "OpenAM Installation Instructions"


###Configuring cf-release for a saml_login deployment

The saml_login deploys the same way as the login-server, with additional configuration parameters.
Enabling saml is done using the `spring_profiles` configuration parameter. 

- Open your infrastructure manifest - for example cf-release/templates/cf-infrastructure-warden.yml
  
  Add your Tomcat JVM options as well as the intended protocol to use (http/https)
  <pre>
      saml_login:
        catalina_opts: -Xmx384m -XX:MaxPermSize=128m
        protocol: http

  </pre>
  Scroll down to your login job and change the template to saml_login, it will be found under 
  <pre>
    jobs: 
      - name: login_z1
        template: saml_login
  </pre>

- Open your cf-jobs.yml manifest and change the template for the login job

  <pre>
      - name: login_z1
        release: (( meta.release.name ))
        template: saml_login
  </pre>  
  
- Open your cf-properties.yml manifest to configure saml_login properties
  
  Please note the spring_profiles setting
  - spring_profiles: saml (uses only  saml with an external SAML provider)

  <pre>
    saml_login: 
      #standard login server configuration
      catalina_opts: (( merge ))
      uaa_certificate: ~
      protocol: https

      links:
        home: (( "https://console." domain ))
        passwd: (( "https://console." domain "/password_resets/new" ))
        signup: (( "https://console." domain "/register" ))
    
      #if you wish to use saml
      spring_profiles: saml
      
      #saml authentication information, only required if 'saml' is part of spring_profiles
      entityid: cloudfoundry-saml-login-server
      idpEntityAlias: vsphere-local
      idpMetadataURL: "https://win2012-sso2:7444/websso/SAML2/Metadata/vsphere.local"  
      serviceProviderKeyPassword: password
      serviceProviderKey: | 
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: DES-EDE3-CBC,231BD428AF94D4C8
        0Nmo90pX8byVS7ZlakMIoXdJSLlxqzi1pN0g1ye2U+9HgTLTLuMwWaPknZ/2NFtK
        rO72ss8uc7xBAoMkOvcMTZCg5P4JDlmuQ31IabzRyOQcAxCPZedgarRnwxT6GUim
        JtkzNPmAAgf1bfUTu/LNt2o01dW+qq+2qiwUxgUBM2xLBmadIWqqTOZbkFc9Xjvl
        /IEnJgp/c49sNh68EpXPlsGJfW7jAh90nlA13H1fpvTsSg2/6wKbRsxxNkpVg0Nq
        bQURQIO6htOLZBPMMpoPILp/KtKkd1zpaZJnbZGDo9AdwfAh9dUbEw8ukJwRg3Xl
        lsptHoMGsGdvgViWZhCB/pAHYLh31G8oVMA/qPB9PNJYIK2aQZdm7yiAdf+m8Jxb
        Do2xBH6XUeHkg2F0LWnC/FjaMRpLuliI9vvJVB7YCQKkMdgNVV0SCx39IiX0rEm5
        8vuuoAH3b7b+maWp5+ffriNIcEFSlcmTPIgqZBboIORBNXZnHTUG7nGIML+nlOK9
        zdvF2vAxchqOKroc6+SGFLNvNQd9S/nLH3vP+aX9iStL55G11+p2tL+bIGMWZj0h
        Z+qqQoogtngRFbjcVoKYerFXbKG6xXzXUc4O3EbvAKvEi0HJodYccP3L7wIer1aY
        VaMF2M05g5KedHosEfvvhU17xS9L4u2SRMZIQ3K8iLNEhZ6bOw6EnzTaKWeffrYr
        UOjfMEgswcHfpxx1iD5T4RTwxuKOgtFhd1QM4enXPsU6uRU5PGSiB/0t6jal6ClF
        PhtIrTwhx0vBR4rySx4raXdLClxxt5vLe826C3uwo/6HTdUsnDvIXA==
        -----END RSA PRIVATE KEY-----
      serviceProviderKeyPassword: password
      serviceProviderCertificate: | 
        -----BEGIN CERTIFICATE-----
        MIIBzzCCATgCCQDTMCX3wJYrVDANBgkqhkiG9w0BAQUFADAsMSowKAYDVQQDFCFz
        YW1sX2xvZ2luLE9VPXRlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMjMzOTU4
        WhcNMTQwNzAyMjMzOTU4WjAsMSowKAYDVQQDFCFzYW1sX2xvZ2luLE9VPXRlc3Qs
        Tz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANYBRuep
        WaoNA7/RsOUVlmOzxbhtfW8AstGXjsWbAmmg8NSruRlNuMz1WdCeESM3zBqLSyp8
        Vf3j3ExzB2qquDbPXNA1k4EqgNya2E+6n3KsgVLCWQm4W46Pd7C6QswrR6JgUKaW
        6KI8BgyJQ9wjL/nR8uqZouJJyRSLuIaGXIuXAgMBAAEwDQYJKoZIhvcNAQEFBQAD
        gYEAXOojarkGv5nVZqTuY8BRM/TRt1oby3i0VRG70l0PcDlWft52aSvCd3t8ds2S
        h92cXLz8nvHEBaBTkxTLtf2/h5x2KQhXyHoU1UU+JjOegoF+LD6KdmaVk2l35Na5
        1V2AHsj+yDrJ9aKwt86jbBbcFkRphdkn5ivq71GCWRfcpZE=
        -----END CERTIFICATE-----
      nameidFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  
  </pre>  
  
  
  
  