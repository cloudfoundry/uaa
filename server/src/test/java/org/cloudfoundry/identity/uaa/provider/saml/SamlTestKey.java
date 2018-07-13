/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.security.saml.key.SimpleKey;

/*

DST=idp
openssl genrsa -des3 -passout pass:${DST}password -out server.key 1024
openssl req -passin pass:${DST}password -new -key server.key -out server.csr \
  -subj "/C=US/ST=Washington/L=Vancouver/O=Spring Security SAML/OU=${DST}/CN=${DST}.spring.security.saml"
openssl x509 -passin pass:${DST}password -req -days 3650 -in server.csr -signkey server.key -out server.crt

 */
public enum SamlTestKey {
    RSA_TEST_KEY(
        "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
            "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
            "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
            "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
            "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
            "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
            "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
            "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
            "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
            "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
            "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
            "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
            "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
            "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
            "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
            "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
            "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
            "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
            "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
            "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
            "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
            "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
            "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
            "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
            "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
            "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
            "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
            "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
            "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
            "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
            "-----END CERTIFICATE-----",
            "password"
    ),

    SP_RSA_KEY(
        "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,0697FC7BCAE519B6\n" +
            "\n" +
            "lZ2EtAXVJOrq/r56p6e0eg9y53EpEE9iF13yksA7AW07/Q0FAuyRM5UDZRSewpxr\n" +
            "yFqvjLS0PFAFZQNOlKVR6IF/SCHjBbxxKFSUxUtuMiC8x5Xi+iJDyDbHS1Ei7jyB\n" +
            "CYU0B20qwg//Q5jPEfF4FrM0OfUpDO8jG8n5Al3N2uc9//oNUEIyY8H8pa+zxWrk\n" +
            "sINaMNFKE+UJhEhXItAaApZjUNRdD54OaF9zYRKRcCquiV5JwpUMMCoHOLfzY01C\n" +
            "Iqwc1M2CvFGdkpkmlBwBs9c/MOEoCzLCgJSKk6HeIMa5dP00x9S0zxwf18AYfyGO\n" +
            "PujuenP7xks7Dw7bKW/H092K6vCSM94V+Ot5bTyia/P+rDacXj4dnBR3sRNAIz73\n" +
            "XcbQ3v5iJ+dD65R2tKuQMs6lKvXOutL2sofUid7+LLh5ajRiK+xf0fn9etO40GPv\n" +
            "NSSy9J8guV1UBR+tOUqa2JUHFd3TndPrxwtSMh7Mdhk7LiClf1v/uuvOMHEnhDI0\n" +
            "I2ScT4e9ukTztXCfap1kRQGsz72hXrVK4G4XG0bij6iMeTv9UJUR//uYOtSzdFK/\n" +
            "62EDJiFIRwFW/UyjMyCT2Cok19Gt33gwz1AkoP5O2dlU0Sb7qrHDbQ0kaUqs82ZY\n" +
            "akHZTaXmRMD/iMlbVGHdxnbGUKgFPqnPt9pY/T1792sJObu1G0gNZbRtKW9AxsVh\n" +
            "jrUvE1wXDbLHzW5ZjHs02gkusRwaTi9Hbw8FZER6CtOeMtXdQUVU+MnPYg6M0kFj\n" +
            "0HPsK4qcVwUggZFl5/U2ByJlWSPwmHYg8cl2oac7dt6pNZhTY5lQ3g==\n" +
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIICgTCCAeoCCQDtqkmhbmvARzANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
            "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
            "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
            "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA0MzAyMTA1MTNaFw0yODA0\n" +
            "MjcyMTA1MTNaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
            "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
            "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBRIHAaQLxTLJQDt8NDz/zT1PZ\n" +
            "uwu9pwo44zGLnrbU22qXLuNhbur/nqxEpIJBjy1BYyeGvlcGhOXTu1uThZdmKC71\n" +
            "KwGNgTHdE1ciC/Fu/GMtgoVsQujtOV92Fw5mMcJR7yNIsGP0+4nCWj41M+4h/Edb\n" +
            "UawCWNWEqrgyvDrGWwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBALcvf1p3lOPlgcJN\n" +
            "v2JUh1Z53VWbOOPRqm31AXCN5rvb52nqGi5gz1jJz1oXliBRsvOt5cDP89uUTAQ2\n" +
            "HWuJTlm0M/1dJh1CJ7cjugoFEMYCjEA72CS8wYjujtZhXZYFdI/eMeJw0IoRqVh3\n" +
            "mZqU4V1B7udBKD/Kmbwpm4XZI/An\n" +
            "-----END CERTIFICATE-----",
            "sppassword"
    ),

    IDP_RSA_KEY(
        "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,2134AC4FF1C9190B\n" +
            "\n" +
            "C3tnCrkGRiGwX2llAfdOcBkIt8QSN3h1dPHUzTsZi8jAxZSAGrYCC4ardNjB/rL1\n" +
            "7T7TenvNOMCduXDiOvPmPzBCPbV3ZnM+yaqfgv7GIdnLh5RQLEQs8mOsKDdvjl5O\n" +
            "ckBGMvriUBtwMx3yA9ghHRUJycb2W6/s7rdPeO+SaoDK96uEGnSshXTGR0Rdmfl2\n" +
            "Ma6iOKcexXPaa8qZ7Hl/PZXJByAcGkKYzOS7tCI6V7JncdhFvvZT9a6pLE+31Qh7\n" +
            "BfS09G8l7PVOc0KxUEQTnOEGK204FZ9Vbrfdf6HP86ATDAtAe7Tc9woBAikcCEBC\n" +
            "bSB4UHR+vJIQV74ICH0a/AZbzieoGKmSXzEF++Hl9MgbJ+BJ9v+89Q+A8ECrzsh1\n" +
            "uDx36DB5Hv+Auqct8O/Q8SAQYOoJKR8GAplqRWX/79o/J5KUS9W/tyx9TNcUTn4O\n" +
            "HSirh4FjPMyziW74WoIsOAFW7i0wB8YQxVLm3q4vPG65WSeODl7V3iEB8o/hwIme\n" +
            "8k12nRcI3yzviDaQE9x65b/CdAI22u+Vx/LXfxEFoLuCAwmusFo+AJ+GfIefR7Ae\n" +
            "HfxxIclsyBCFuEOB+EINJ6hfJDtRtd5rlayc1fHTRD/UukuSLbCDTaFpvUMyPmdH\n" +
            "Jome2QpqEzitIPvhRriFMl+Jxouerj3ECXEXeFMDQWWqymshRxBuPJQOpHzxA+W4\n" +
            "BL1Fgk9bw5ee4l1D1LuhTG1Xzg7JxAZF0UlyHDtXn/mT7Op+OhRC4+4Oi4HZDPBC\n" +
            "35aC/u+Fa6+99Uv84VsXye+qbmlXCUwCSArvlJTJLD0=\n" +
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIChTCCAe4CCQCgBBgKZvR7JTANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC\n" +
            "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
            "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UE\n" +
            "AwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1sMB4XDTE4MDQzMDIxMDYyNloXDTI4\n" +
            "MDQyNzIxMDYyNlowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9u\n" +
            "MRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0eSBT\n" +
            "QU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHku\n" +
            "c2FtbDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAno7/WHeU1HWOz7YVsp9x\n" +
            "IGRy3Q09YmMGUdkF7z9pI7NGiwqV/Wgt7DAOW8CALtx5uCDJ+PCbZ0h+tRpo+fqS\n" +
            "5ONC4UpDOf518Dr+Y5hMHN1j5T6lMFAQFfPdTNuGBZ0toA+zHpOZMR1/sLKnfnWk\n" +
            "LkUOoZkO8MuvfqmthZVftG0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQBwt/VCstC8\n" +
            "PqbyRjSVQFl+n/NrAZK5m0J/OGraG8qTk+pouHLRMR6Xgov3waEHvaMKRWpSRiNF\n" +
            "d0jihaQh/QTMZr8jCoKUaoV1XGWIxoKEvB7/xzixs2X2M85Ud790H7PT9GbDqZuS\n" +
            "Nud1HItVxaexFvoreh+D1+bBE0fLZ9K+Sw==\n" +
            "-----END CERTIFICATE-----",
            "idppassword"
    );


    private final String privatePem;
    private final String publicPem;
    private final String passphrase;

    SamlTestKey(String privatePem, String publicPem, String passphrase) {
        this.privatePem = privatePem;
        this.publicPem = publicPem;
        this.passphrase = passphrase;
    }

    public SimpleKey getSimpleKey(String alias) {
        return new SimpleKey(alias, getPrivate(), getPublic(), getPassphrase(), null);
    }

    public String getPrivate() {
        return privatePem;
    }

    public String getPublic() {
        return publicPem;
    }

    public String getPassphrase() {
        return passphrase;
    }

    public SimpleKey getPublicKey(String alias) {
        return new SimpleKey(alias, null, getPublic(), null, null);
    }

}
