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
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertNotNull;


public class KeyWithCertTest {

    @BeforeClass
    public static void addProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

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

    public static final String encryptedKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,BE03AC562D734AB1\n" +
            "mvMS20ddwCJ6A+ABJKWViGTgLpWUVA5ZqKYU6Q3N+le769s4uygcMOtvTcjgH46E\n" +
            "3gIDR+Qt+UO/Yv+EgIJnga+vLMayjg/pl2bR8p1lK7gUkAb7DwDviySSi18tAt0O\n" +
            "NTyJEzy6G+WnlSs+3tzRUCneaoFB1/LDdUSOzaSLRtU/r+Vt/9BYBQbZMalnSQRE\n" +
            "U17VhISbfj4MgNIfZU+7+ALfE0+Muno4WDk+IJXArAk7wckF6NO7M4EKHlLzrHI0\n" +
            "+PccNBKN/rAevYZrZOmGCw4jKu5JJDtt6SgQJIp/XGEZlv+KD2cWPBC4nj7nJHAz\n" +
            "ezt9SfnL8jQlClTwQyPHjwDPlL/WHQrBpxpFF83FnN8B02DWwXQE2oTC7RtijQVT\n" +
            "NKto/vSODK0RfaulLHNx6RvJF0YFWSSofTm0G5TLwWCCrVekK0N5zAYPeG9LgjlG\n" +
            "4xILPSE+Y6hYIVN2gXNZOVB8T5O+Jf1KQlmMnZ9A5o1gcUJq0rCBa6i2D2rveQGE\n" +
            "eLm3BgyMp5v0JsyuzDBuxVWSgJFt+KHz/mhdgdG8End3QBF2BBaHpLP0+5BqIZHX\n" +
            "NYCDBwWK/k40oxT8KLdFfkBU48Yndq7ARFdq3YzPU6FdSpgwZM5p8HYkl1THcskI\n" +
            "Ri7zVHxpm0tPZqqqgzr6HBvSiQhACT4dOXV5V8bEoL5tlyuZllq2MBayl9yd0+bq\n" +
            "6hVZXUYewtPyE2Wj2PDr2F7fGtYhKcrnQxH63w3OhIzgkxUTQ63h710QDJjOtYCm\n" +
            "/PCAsNBePrnjrHHxMxkMVCtTYSeBePk0vkUtFOE5hIc=\n" +
            "-----END RSA PRIVATE KEY-----\n";

    public static final String goodCert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIC6TCCAlICCQDN85uMN+4K5jANBgkqhkiG9w0BAQsFADCBuDELMAkGA1UEBhMC\n" +
            "VVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQK\n" +
            "DBRQaXZvdGFsIFNvZnR3YXJlIEluYzEeMBwGA1UECwwVQ2xvdWRmb3VuZHJ5IElk\n" +
            "ZW50aXR5MRswGQYDVQQDDBJ1YWEucnVuLnBpdm90YWwuaW8xKDAmBgkqhkiG9w0B\n" +
            "CQEWGXZjYXAtZGV2QGNsb3VkZm91bmRyeS5vcmcwHhcNMTUwMzAyMTQyMDQ4WhcN\n" +
            "MjUwMjI3MTQyMDQ4WjCBuDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYD\n" +
            "VQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRQaXZvdGFsIFNvZnR3YXJlIElu\n" +
            "YzEeMBwGA1UECwwVQ2xvdWRmb3VuZHJ5IElkZW50aXR5MRswGQYDVQQDDBJ1YWEu\n" +
            "cnVuLnBpdm90YWwuaW8xKDAmBgkqhkiG9w0BCQEWGXZjYXAtZGV2QGNsb3VkZm91\n" +
            "bmRyeS5vcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN0u5J4BJUDgRv6I\n" +
            "h5/r7rZjSrFVLL7bl71CzBIaVk1BQPYfBC8gggGAWmYYxJV0Kz+2Vx0Z96OnXhJk\n" +
            "gG46Zo2KMDudEeSdXou+dSBNISDv4VpLKUGnVU4n/L0khbI+jX51aS80ub8vThca\n" +
            "bkdY5x4Ir8G3QCQvCGKgU2emfFe7AgMBAAEwDQYJKoZIhvcNAQELBQADgYEAXghg\n" +
            "PwMhO0+dASJ83e2Bu63pKO808BrVjD51sSEMb0qwFc5IV6RzK/mkJgO0fphhoqOm\n" +
            "ZLzGcSYwCmj0Vc0GO5NgnFVZg4N9CyYCpDMeQynumlrNhRgnZRzlqXtQgL2bQDiu\n" +
            "coxNL/KY05iVlE1bmq/fzNEmEi2zf3dQV8CNSYs=\n" +
            "-----END CERTIFICATE----\n";

    @Test(expected = CertificateException.class)
    public void test_invalid_cert() throws Exception {
        new KeyWithCert(key, password, cert);

    }
    @Test()
    public void test_valid_cert() throws Exception {
        new KeyWithCert(encryptedKey, password, goodCert);
    }

    @Test()
    public void cert_only() throws Exception {
        assertNotNull(new KeyWithCert(goodCert).getCert());
    }
}