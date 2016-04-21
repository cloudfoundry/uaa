/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;
import java.security.cert.CertificateException;


public class KeyWithCertTest {
    public static final String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
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
    public static final String cert = "-----BEGIN CERTIFICATE-----\n" +
            "FILIPMIIEJTCCA46gAwIBAgIJANIqfxWTfhpkMA0GCSqGSIb3DQEBBQUAMIG+MQswCQYD\n" +
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
            "-----END CERTIFICATE-----\n";
    public static final String password = "password";

    @Test(expected = CertificateException.class)
    public void test_invalid_cert() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        new KeyWithCert(key, password, cert);

    }
}