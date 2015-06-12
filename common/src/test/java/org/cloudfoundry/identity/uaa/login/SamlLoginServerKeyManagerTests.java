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
            "MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3\n" +
            "AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU\n" +
            "JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB\n" +
            "AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz\n" +
            "a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb\n" +
            "RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r\n" +
            "LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr\n" +
            "sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6\n" +
            "J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL\n" +
            "f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC\n" +
            "AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf\n" +
            "oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH\n" +
            "waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==\n" +
            "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEJTCCA46gAwIBAgIJANIqfxWTfhpkMA0GCSqGSIb3DQEBBQUAMIG+MQswCQYD\n" +
            "VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5j\n" +
            "aXNjbzEdMBsGA1UEChMUUGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Ns\n" +
            "b3VkIEZvdW5kcnkgSWRlbnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2Yt\n" +
            "YXBwLmNvbTEfMB0GCSqGSIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzAeFw0xNTA1\n" +
            "MTQxNzE5MTBaFw0yNTA1MTExNzE5MTBaMIG+MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
            "CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChMU\n" +
            "UGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Nsb3VkIEZvdW5kcnkgSWRl\n" +
            "bnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2YtYXBwLmNvbTEfMB0GCSqG\n" +
            "SIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n" +
            "gYkCgYEA30y2nX+kICXktl1yJhBzLGvtTuzJiLeOMWi++zdivifyRqX1dwJ5MgdO\n" +
            "sBWdNrASwe4ZKONiyLFRDsk7lAYq3f975chxSsrRu1BLetBZfPEmwBH7FCTdYtWk\n" +
            "lJbpz0vzQs/gSsMChT/UrN6zSJhPVHNizLxstedyxxVVts644U8CAwEAAaOCAScw\n" +
            "ggEjMB0GA1UdDgQWBBSvWY/TyHysYGxKvII95wD/CzE1AzCB8wYDVR0jBIHrMIHo\n" +
            "gBSvWY/TyHysYGxKvII95wD/CzE1A6GBxKSBwTCBvjELMAkGA1UEBhMCVVMxEzAR\n" +
            "BgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHTAbBgNV\n" +
            "BAoTFFBpdm90YWwgU29mdHdhcmUgSW5jMSQwIgYDVQQLExtDbG91ZCBGb3VuZHJ5\n" +
            "IElkZW50aXR5IFRlYW0xHDAaBgNVBAMTE2lkZW50aXR5LmNmLWFwcC5jb20xHzAd\n" +
            "BgkqhkiG9w0BCQEWEG1hcmlzc2FAdGVzdC5vcmeCCQDSKn8Vk34aZDAMBgNVHRME\n" +
            "BTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAL5j1JCN5EoXMOOBSBUL8KeVZFQD3Nfy\n" +
            "YkYKBatFEKdBFlAKLBdG+5KzE7sTYesn7EzBISHXFz3DhdK2tg+IF1DeSFVmFl2n\n" +
            "iVxQ1sYjo4kCugHBsWo+MpFH9VBLFzsMlP3eIDuVKe8aPXFKYCGhctZEJdQTKlja\n" +
            "lshe50nayKrT\n" +
            "-----END CERTIFICATE-----";
        String password = null;

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
        Credential credential = keyManager.getDefaultCredential();
        assertNotNull(credential.getPrivateKey());
        assertNotNull(credential.getPublicKey());
        assertNotNull(credential);
        System.out.println("certificate = " + certificate);
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
