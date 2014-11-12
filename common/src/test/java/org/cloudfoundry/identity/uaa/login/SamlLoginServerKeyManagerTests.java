/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import static org.junit.Assert.assertNotNull;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.xml.security.credential.Credential;

public class SamlLoginServerKeyManagerTests {

    private SamlLoginServerKeyManager keyManager = null;

    @Test
    public void testWithWorkingCertificate() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "ANK8mv+mUzhPH/8iTdMsZ6mY4r4At/GZIFS34L+/I0V2g6PkZ84VBgodqqV6Z6NY\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "password";

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
        Credential credential = keyManager.getDefaultCredential();
        assertNotNull(credential.getPrivateKey());
        assertNotNull(credential.getPublicKey());
        assertNotNull(credential);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWithWorkingCertificateInvalidPassword() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "ANK8mv+mUzhPH/8iTdMsZ6mY4r4At/GZIFS34L+/I0V2g6PkZ84VBgodqqV6Z6NY\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "vmware";

        try {
            keyManager = new SamlLoginServerKeyManager(key, password, certificate);
            Assert.fail("Password invalid. Should not reach this line.");
        } catch (Exception x) {
            if (x.getClass().getName().equals("org.bouncycastle.openssl.EncryptionException")) {
                throw new IllegalArgumentException(x);
            } else if (x.getClass().equals(IllegalArgumentException.class)) {
                throw x;
            }
        }
    }

    @Test
    public void testWithWorkingCertificateNullPassword() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIICXAIBAAKBgQDFOKafzTldEfTIfixO2AaYO4BJwNFkcGnlpSuku54st7wpFD37\n" +
                        "+//8TbK7uJ1+kQzvhnxxgTpJmlZci4zs268IaORj1mN2XKnPfXHiaBmNsK4/Mer/\n" +
                        "y2TZ9pUo7I5dDYaXucvB+ZPdV1m2wp4PsRM9sWuQGMNk16TW64Gwy24FpQIDAQAB\n" +
                        "AoGAKBxyfxPNM+mgAFrxBgQXq0SGvflSXPwj/YnPS4zBCdVAlpZAWQySrqzayiUt\n" +
                        "Gv3DRL/0dV1UDn4uTFoxikbP3Slpxl/fIi9onpERnads8ao3ZapYjUGNWsugq/lo\n" +
                        "SJG7DtSD2ZZApZRJ2JxtUioSPL7fTUBpArpkdHPQtZhZTEECQQDvk1NSaA3e2DLR\n" +
                        "zg89c+Gb/MwdeVowYprDuimqbnT/Lvll8XsPp+W81pv72sD9LpCffdFDm9E6X6tk\n" +
                        "q5nYEiTRAkEA0r38uIBaSaOh+jWMRorW3ofGNZvjmevnQOy2gOem3qkKyxw/nQjg\n" +
                        "NiupFuSF2wI4AYGmfBItnxddugSPlXsYlQJATu1zeuerAiqp+3LulGlT/4b2XBN5\n" +
                        "wg0KPcdcKLkBNHzuT0aSK2M+DcuKUhwMjpzDqrfRtHtmH9wa5Cygn43CsQJACCrs\n" +
                        "3Im89hWtdXEV2rYO1dkVSYadL54A/HcwK5bO1NpgXLbfkEqDxhWzG/wHZBGV8hkA\n" +
                        "Rta9hej17Pu4RObccQJBAKs/bHRDXp+yPhVS4HVwhzDALtK5z1nn+dz3U1AxVJkU\n" +
                        "L+W+bjRi0v91WH5N6lyhxGNCM0lV3DUJaimFk+N+jp0=\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIBzzCCATgCCQCWnZlNikBhATANBgkqhkiG9w0BAQUFADAsMSowKAYDVQQDFCFz\n" +
                        "YW1sX2xvZ2luLE9VPXRlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAzMTgwMzUx\n" +
                        "WhcNMTQwNzAzMTgwMzUxWjAsMSowKAYDVQQDFCFzYW1sX2xvZ2luLE9VPXRlc3Qs\n" +
                        "Tz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMU4pp/N\n" +
                        "OV0R9Mh+LE7YBpg7gEnA0WRwaeWlK6S7niy3vCkUPfv7//xNsru4nX6RDO+GfHGB\n" +
                        "OkmaVlyLjOzbrwho5GPWY3Zcqc99ceJoGY2wrj8x6v/LZNn2lSjsjl0Nhpe5y8H5\n" +
                        "k91XWbbCng+xEz2xa5AYw2TXpNbrgbDLbgWlAgMBAAEwDQYJKoZIhvcNAQEFBQAD\n" +
                        "gYEAcahI6BwiVod/mByeTONw7yjfgYJWjtlrVMIdUwOvtuXY0carOzSL1rJTCSa1\n" +
                        "qQQ7uv1sLAI4L/IqvjCwzJ5h7iuY4Uhuxyyy5HAB9hIdE35Jsny7datvJHKL85FA\n" +
                        "9U1DYM28B69irMgw+w47v9t9U72jvG2Ikq6l4fEFe94XRM8=\n" +
                        "-----END CERTIFICATE-----";
        String password = null;

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
        Credential credential = keyManager.getDefaultCredential();
        assertNotNull(credential.getPrivateKey());
        assertNotNull(credential.getPublicKey());
        assertNotNull(credential);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWithWorkingCertificateIllegalKey() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "ANK8mv+mUzhPH/8iTdMsZ6mY4r4At/GZIFS34L+/I0V2g6PkZ84VBgodqqV6Z6NY\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "password";

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWithNonWorkingCertificate() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "password";

        try {
            keyManager = new SamlLoginServerKeyManager(key, password, certificate);
            Assert.fail("Key/Cert pair is invalid. Should not reach this line.");
        } catch (Exception x) {
            if (x.getClass().getName().equals("org.bouncycastle.openssl.PEMException")) {
                throw new IllegalArgumentException(x);
            } else if (x.getClass().getName().equals("org.bouncycastle.openssl.EncryptionException")) {
                throw new IllegalArgumentException(x);
            } else if (x.getClass().equals(IllegalArgumentException.class)) {
                throw x;
            }
        }
    }
}
