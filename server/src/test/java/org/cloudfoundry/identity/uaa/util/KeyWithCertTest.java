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
import org.bouncycastle.util.encoders.DecoderException;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertNotNull;

public class KeyWithCertTest {

    @BeforeClass
    public static void addProvider() {
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

    public static final String invalidCert = "-----BEGIN CERTIFICATE-----\n" +
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

    // openssl req -out cert.pem -nodes -keyout private.key -newkey rsa:2048 -new -x509
    public static final String opensslCert = "-----BEGIN CERTIFICATE-----\n" +
        "MIIDXTCCAkWgAwIBAgIJAOpOBuLToBXJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n" +
        "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n" +
        "aWRnaXRzIFB0eSBMdGQwHhcNMTcwNzE0MTcxNDE4WhcNMTcwODEzMTcxNDE4WjBF\n" +
        "MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n" +
        "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
        "CgKCAQEA3+07F4S5Fz3wv/UFm/OWsJXm6s3pKI2mp4fSAY8rx9+0cyLAHsedWzeq\n" +
        "5uKcDeRW858DOdnClaTOZC73FcvOmv1bw2eYcmfsbqHEhyR0dp+rDHt/7pr6kajC\n" +
        "yUvAW+hoRRSMpooiZckxrjJ7LOa5iqRyZRwshfGN+mFSygfVguMDKrsE2rvpK6/K\n" +
        "tkG/lcToLHiw4OnMnZ9ocrNRDAoCkzKGZTLJkUEr3MgOKmr2EO0P6KOAmNnOEmCf\n" +
        "05ohcrUXeFZVnS5MMUzoGAOzBstZhA0dd7l297IDnWH9uIhCANCvZ9sovZWz/o3J\n" +
        "pc2LyXsaI1cV7O1cGV4aEEn8zzWWGwIDAQABo1AwTjAdBgNVHQ4EFgQUXBO1+qo7\n" +
        "w6iiiv1pnm+zdrQ3CzkwHwYDVR0jBBgwFoAUXBO1+qo7w6iiiv1pnm+zdrQ3Czkw\n" +
        "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAT78lT5VEIetWPGk3szPz\n" +
        "CT9zNpR1F+7o3rvRTI6Psyjz4tGlyX5iU0Z99Xa9yimIEhWme2UVsgQ9uOzk2IgH\n" +
        "wMbB2TTP/RRK5+eO4BUu4zWWIXsIcfC6Rqw9Y3Hki+mRpuWMv+5pcOz/H+aYeSfy\n" +
        "WvVYfRZJOhcztysII4HWIxw8qqwBrf5kX8IRKZXay+A2W04A6kjjX3zfN2OzljTA\n" +
        "jZbtHedUGxSHvK8x6tHEwS0lZ9eZh+V4DWyRvrunwDCtA7zJQmrJd1qbM84H/1C8\n" +
        "cAC6dglvc82n1BTAZbZwWHYt+Ro3Vp0GMPsZLOXJ0g03LbkhXg4krwXjJPD42nus\n" +
        "3A==\n" +
        "-----END CERTIFICATE-----\n";

    public static final String opensslPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDf7TsXhLkXPfC/\n" +
        "9QWb85awlebqzekojaanh9IBjyvH37RzIsAex51bN6rm4pwN5FbznwM52cKVpM5k\n" +
        "LvcVy86a/VvDZ5hyZ+xuocSHJHR2n6sMe3/umvqRqMLJS8Bb6GhFFIymiiJlyTGu\n" +
        "Mnss5rmKpHJlHCyF8Y36YVLKB9WC4wMquwTau+krr8q2Qb+VxOgseLDg6cydn2hy\n" +
        "s1EMCgKTMoZlMsmRQSvcyA4qavYQ7Q/oo4CY2c4SYJ/TmiFytRd4VlWdLkwxTOgY\n" +
        "A7MGy1mEDR13uXb3sgOdYf24iEIA0K9n2yi9lbP+jcmlzYvJexojVxXs7VwZXhoQ\n" +
        "SfzPNZYbAgMBAAECggEAdEfMl7nkI52Wlxe1gfZMGga9ktC6csSb9gMhmo2uPmx8\n" +
        "WA2Dlngxzlxp8ttaDhy0ym2YT0I1OWALjRqWVEsxTmqibCYvk7lDnW+Djmnv0Gm5\n" +
        "eRHorQ7tbxYjkEQ174QQIU86eoDgu9puYfb036wwTT536OlodWWqRIqlYyQOS5h+\n" +
        "KURvuQkH7CT30swTun11hHibNomxPd97D49aYqr86vrNKYRrVWuruc3OO9ofFaWO\n" +
        "hRuLVivLiuGfFMtkVun2V9ropRArHeSOHPfyCUETJIcyrKPxk7ack0U/Nq9uf3Rd\n" +
        "z9iImQkqMSMvaYmsqIM5qjgMqU+aXfj98l1v0hYvAQKBgQDzoC23vjx01as1BVIA\n" +
        "Z0fc5t+LSonhrKphHnHxxUx7pcmS5HrBCL4Rv+6HL15zCfTkYdt5w+6hByJMpDL4\n" +
        "ZwrdyoI1fL21PSo/TdzNLtgB6FUtYqrUSSFAG3fLN2OYqDW5vxumsFwjn1YmKG1f\n" +
        "emTjNE422oQv/xVsjmj7tgc9CQKBgQDrTOjTVChO/H7WgV20TM8/fg9XD4mfimhD\n" +
        "g9apKReOtKniBL0sFcJH7XpDoNahPRhk+iDY16IbLknstnxGRml+Y63ZHbnD+1v6\n" +
        "vdR15vjJECWHdn8u1y9FqOWa4oXAOO4G1q1FQmjXEIX8svyXSkX65Qg3w9h5oYpN\n" +
        "nhPHVJenAwKBgQDsCOmiVq5uJ8GLSg9LksTeMdStOFdkDQy5sWyF6DiUp2gnaDPC\n" +
        "J/02ZzTrRqqEXEYmquSgEYN2AdpqVL+JSRQPFC+ZMLUADjWLRZ3CMTtYhcdYhHqr\n" +
        "1/peCP7EJXLaKUZ8IrrggYeTf8FQkOR+l699LWUF4iol8kbIeSUfkhlrOQKBgQC2\n" +
        "H7NeTxdb+6eZFEyZD5KiTEpHUqltKU4GY/c0u6+WL1QGszBQ/Q6BadhmnAlEh+tn\n" +
        "zQq7jDvW2f8yDxUlt75Tq4eWM6HjhZzt+RyHnZ0W0z6ZGSjb8oaOXmpJdeecnvPt\n" +
        "qyA2KW7Id+udalSELWL5DWlM8HOPwW8xIJeig2FWTQKBgBkGMD+32aXltymx0SIo\n" +
        "JVfL+kPBtPyDdAJbxJu8fFfhzbFGlLI5qVQnrzjgjhnkHcnvmTu2ZgPStArpJqUk\n" +
        "4KNl3HZLG6vreo137aKjXzshdNwx1Yzw0PigLAwLgx7APFZYkM0qpE0JPyFeFORu\n" +
        "XXDWlzK1YYlKSBuSsm9VWfXq\n" +
        "-----END PRIVATE KEY-----\n";

    // openssl req -out cert.pem -nodes -keyout private.key
    //   -newkey ec:<(openssl ecparam -name secp224r1) -new -x509
    public static final String ecCertificate = "-----BEGIN CERTIFICATE-----\n" +
        "MIIBvjCCAWygAwIBAgIJAK/rmJC9QdjcMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\n" +
        "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\n" +
        "aXRzIFB0eSBMdGQwHhcNMTcwNzE0MTgxNjU2WhcNMTcwODEzMTgxNjU2WjBFMQsw\n" +
        "CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\n" +
        "ZXQgV2lkZ2l0cyBQdHkgTHRkME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEY83DklF/\n" +
        "qOPmJkASvf25MaDvzF7w+MeYaBZHiC18y9mayfAcKPti4MbPR6ADAo9NxKbdsZjA\n" +
        "13+jUDBOMB0GA1UdDgQWBBQxUP7SZIeKaQmFaAIBDRCJjUcXbzAfBgNVHSMEGDAW\n" +
        "gBQxUP7SZIeKaQmFaAIBDRCJjUcXbzAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMC\n" +
        "A0AAMD0CHCR7SmBxeufWpfAECH+Zp/2NMhhyIuYoeOThi3wCHQCyJmYQs8xHzC17\n" +
        "yMyZj8YGfSSXgdWkp381P0gl\n" +
        "-----END CERTIFICATE-----\n";

    public static final String ecPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
        "MHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBz+XVZZoypybMtDZWBVcrPu\n" +
        "IiVn3yZ+kzF+f2NyoTwDOgAEY83DklF/qOPmJkASvf25MaDvzF7w+MeYaBZHiC18\n" +
        "y9mayfAcKPti4MbPR6ADAo9NxKbdsZjA138=\n" +
        "-----END PRIVATE KEY-----\n";

    @Test(expected = DecoderException.class)
    public void testInvalidCert() throws Exception {
        new KeyWithCert(key, password, invalidCert);
    }

    @Test
    public void testValidCert() throws Exception {
        new KeyWithCert(encryptedKey, password, goodCert);
    }

    @Test

    public void testEllipticCurve() throws Exception {
        new KeyWithCert(ecPrivateKey, "", ecCertificate);
    }

    @Test
    public void testEmbeddedPrivateKey() throws Exception {
        new KeyWithCert(opensslPrivateKey, "", opensslCert);
    }

    @Test(expected = CertificateException.class)
    public void testKeyMismatch() throws Exception {
        new KeyWithCert(key, "", opensslCert);
    }

    @Test
    public void testCertOnly() throws Exception {
        assertNotNull(new KeyWithCert(goodCert).getCertificate());
    }
}
