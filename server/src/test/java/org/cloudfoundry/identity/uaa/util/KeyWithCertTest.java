/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class KeyWithCertTest {

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    private static final String KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3
            AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU
            JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB
            AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz
            a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb
            RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r
            LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr
            sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6
            J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL
            f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC
            AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf
            oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH
            waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==
            -----END RSA PRIVATE KEY-----""";

    public static final String INVALID_CERT = """
            -----BEGIN CERTIFICATE-----
            FILIPMIIEJTCCA46gAwIBAgIJANIqfxWTfhpkMA0GCSqGSIb3DQEBBQUAMIG+MQswCQYD
            VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5j
            aXNjbzEdMBsGA1UEChMUUGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Ns
            b3VkIEZvdW5kcnkgSWRlbnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2Yt
            YXBwLmNvbTEfMB0GCSqGSIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzAeFw0xNTA1
            MTQxNzE5MTBaFw0yNTA1MTExNzE5MTBaMIG+MQswCQYDVQQGEwJVUzETMBEGA1UE
            CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChMU
            UGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Nsb3VkIEZvdW5kcnkgSWRl
            bnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2YtYXBwLmNvbTEfMB0GCSqG
            SIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
            gYkCgYEA30y2nX+kICXktl1yJhBzLGvtTuzJiLeOMWi++zdivifyRqX1dwJ5MgdO
            sBWdNrASwe4ZKONiyLFRDsk7lAYq3f975chxSsrRu1BLetBZfPEmwBH7FCTdYtWk
            lJbpz0vzQs/gSsMChT/UrN6zSJhPVHNizLxstedyxxVVts644U8CAwEAAaOCAScw
            ggEjMB0GA1UdDgQWBBSvWY/TyHysYGxKvII95wD/CzE1AzCB8wYDVR0jBIHrMIHo
            gBSvWY/TyHysYGxKvII95wD/CzE1A6GBxKSBwTCBvjELMAkGA1UEBhMCVVMxEzAR
            BgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHTAbBgNV
            BAoTFFBpdm90YWwgU29mdHdhcmUgSW5jMSQwIgYDVQQLExtDbG91ZCBGb3VuZHJ5
            IElkZW50aXR5IFRlYW0xHDAaBgNVBAMTE2lkZW50aXR5LmNmLWFwcC5jb20xHzAd
            BgkqhkiG9w0BCQEWEG1hcmlzc2FAdGVzdC5vcmeCCQDSKn8Vk34aZDAMBgNVHRME
            BTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAL5j1JCN5EoXMOOBSBUL8KeVZFQD3Nfy
            YkYKBatFEKdBFlAKLBdG+5KzE7sTYesn7EzBISHXFz3DhdK2tg+IF1DeSFVmFl2n
            iVxQ1sYjo4kCugHBsWo+MpFH9VBLFzsMlP3eIDuVKe8aPXFKYCGhctZEJdQTKlja
            lshe50nayKrT
            -----END CERTIFICATE-----
            """;

    private static final String PASSWORD = "password";

    private static final String ENCRYPTED_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            Proc-Type: 4,ENCRYPTED
            DEK-Info: DES-EDE3-CBC,BE03AC562D734AB1
            mvMS20ddwCJ6A+ABJKWViGTgLpWUVA5ZqKYU6Q3N+le769s4uygcMOtvTcjgH46E
            3gIDR+Qt+UO/Yv+EgIJnga+vLMayjg/pl2bR8p1lK7gUkAb7DwDviySSi18tAt0O
            NTyJEzy6G+WnlSs+3tzRUCneaoFB1/LDdUSOzaSLRtU/r+Vt/9BYBQbZMalnSQRE
            U17VhISbfj4MgNIfZU+7+ALfE0+Muno4WDk+IJXArAk7wckF6NO7M4EKHlLzrHI0
            +PccNBKN/rAevYZrZOmGCw4jKu5JJDtt6SgQJIp/XGEZlv+KD2cWPBC4nj7nJHAz
            ezt9SfnL8jQlClTwQyPHjwDPlL/WHQrBpxpFF83FnN8B02DWwXQE2oTC7RtijQVT
            NKto/vSODK0RfaulLHNx6RvJF0YFWSSofTm0G5TLwWCCrVekK0N5zAYPeG9LgjlG
            4xILPSE+Y6hYIVN2gXNZOVB8T5O+Jf1KQlmMnZ9A5o1gcUJq0rCBa6i2D2rveQGE
            eLm3BgyMp5v0JsyuzDBuxVWSgJFt+KHz/mhdgdG8End3QBF2BBaHpLP0+5BqIZHX
            NYCDBwWK/k40oxT8KLdFfkBU48Yndq7ARFdq3YzPU6FdSpgwZM5p8HYkl1THcskI
            Ri7zVHxpm0tPZqqqgzr6HBvSiQhACT4dOXV5V8bEoL5tlyuZllq2MBayl9yd0+bq
            6hVZXUYewtPyE2Wj2PDr2F7fGtYhKcrnQxH63w3OhIzgkxUTQ63h710QDJjOtYCm
            /PCAsNBePrnjrHHxMxkMVCtTYSeBePk0vkUtFOE5hIc=
            -----END RSA PRIVATE KEY-----
            """;

    private static final String GOOD_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIC6TCCAlICCQDN85uMN+4K5jANBgkqhkiG9w0BAQsFADCBuDELMAkGA1UEBhMC
            VVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQK
            DBRQaXZvdGFsIFNvZnR3YXJlIEluYzEeMBwGA1UECwwVQ2xvdWRmb3VuZHJ5IElk
            ZW50aXR5MRswGQYDVQQDDBJ1YWEucnVuLnBpdm90YWwuaW8xKDAmBgkqhkiG9w0B
            CQEWGXZjYXAtZGV2QGNsb3VkZm91bmRyeS5vcmcwHhcNMTUwMzAyMTQyMDQ4WhcN
            MjUwMjI3MTQyMDQ4WjCBuDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYD
            VQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRQaXZvdGFsIFNvZnR3YXJlIElu
            YzEeMBwGA1UECwwVQ2xvdWRmb3VuZHJ5IElkZW50aXR5MRswGQYDVQQDDBJ1YWEu
            cnVuLnBpdm90YWwuaW8xKDAmBgkqhkiG9w0BCQEWGXZjYXAtZGV2QGNsb3VkZm91
            bmRyeS5vcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN0u5J4BJUDgRv6I
            h5/r7rZjSrFVLL7bl71CzBIaVk1BQPYfBC8gggGAWmYYxJV0Kz+2Vx0Z96OnXhJk
            gG46Zo2KMDudEeSdXou+dSBNISDv4VpLKUGnVU4n/L0khbI+jX51aS80ub8vThca
            bkdY5x4Ir8G3QCQvCGKgU2emfFe7AgMBAAEwDQYJKoZIhvcNAQELBQADgYEAXghg
            PwMhO0+dASJ83e2Bu63pKO808BrVjD51sSEMb0qwFc5IV6RzK/mkJgO0fphhoqOm
            ZLzGcSYwCmj0Vc0GO5NgnFVZg4N9CyYCpDMeQynumlrNhRgnZRzlqXtQgL2bQDiu
            coxNL/KY05iVlE1bmq/fzNEmEi2zf3dQV8CNSYs=
            -----END CERTIFICATE----
            """;

    // openssl req -out cert.pem -nodes -keyout private.key -newkey rsa:2048 -new -x509
    private static final String OPEN_SSL_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAOpOBuLToBXJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMTcwNzE0MTcxNDE4WhcNMTcwODEzMTcxNDE4WjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA3+07F4S5Fz3wv/UFm/OWsJXm6s3pKI2mp4fSAY8rx9+0cyLAHsedWzeq
            5uKcDeRW858DOdnClaTOZC73FcvOmv1bw2eYcmfsbqHEhyR0dp+rDHt/7pr6kajC
            yUvAW+hoRRSMpooiZckxrjJ7LOa5iqRyZRwshfGN+mFSygfVguMDKrsE2rvpK6/K
            tkG/lcToLHiw4OnMnZ9ocrNRDAoCkzKGZTLJkUEr3MgOKmr2EO0P6KOAmNnOEmCf
            05ohcrUXeFZVnS5MMUzoGAOzBstZhA0dd7l297IDnWH9uIhCANCvZ9sovZWz/o3J
            pc2LyXsaI1cV7O1cGV4aEEn8zzWWGwIDAQABo1AwTjAdBgNVHQ4EFgQUXBO1+qo7
            w6iiiv1pnm+zdrQ3CzkwHwYDVR0jBBgwFoAUXBO1+qo7w6iiiv1pnm+zdrQ3Czkw
            DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAT78lT5VEIetWPGk3szPz
            CT9zNpR1F+7o3rvRTI6Psyjz4tGlyX5iU0Z99Xa9yimIEhWme2UVsgQ9uOzk2IgH
            wMbB2TTP/RRK5+eO4BUu4zWWIXsIcfC6Rqw9Y3Hki+mRpuWMv+5pcOz/H+aYeSfy
            WvVYfRZJOhcztysII4HWIxw8qqwBrf5kX8IRKZXay+A2W04A6kjjX3zfN2OzljTA
            jZbtHedUGxSHvK8x6tHEwS0lZ9eZh+V4DWyRvrunwDCtA7zJQmrJd1qbM84H/1C8
            cAC6dglvc82n1BTAZbZwWHYt+Ro3Vp0GMPsZLOXJ0g03LbkhXg4krwXjJPD42nus
            3A==
            -----END CERTIFICATE-----
            """;

    private static final String OPEN_SSL_PRIVATE_KEY = """
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDf7TsXhLkXPfC/
            9QWb85awlebqzekojaanh9IBjyvH37RzIsAex51bN6rm4pwN5FbznwM52cKVpM5k
            LvcVy86a/VvDZ5hyZ+xuocSHJHR2n6sMe3/umvqRqMLJS8Bb6GhFFIymiiJlyTGu
            Mnss5rmKpHJlHCyF8Y36YVLKB9WC4wMquwTau+krr8q2Qb+VxOgseLDg6cydn2hy
            s1EMCgKTMoZlMsmRQSvcyA4qavYQ7Q/oo4CY2c4SYJ/TmiFytRd4VlWdLkwxTOgY
            A7MGy1mEDR13uXb3sgOdYf24iEIA0K9n2yi9lbP+jcmlzYvJexojVxXs7VwZXhoQ
            SfzPNZYbAgMBAAECggEAdEfMl7nkI52Wlxe1gfZMGga9ktC6csSb9gMhmo2uPmx8
            WA2Dlngxzlxp8ttaDhy0ym2YT0I1OWALjRqWVEsxTmqibCYvk7lDnW+Djmnv0Gm5
            eRHorQ7tbxYjkEQ174QQIU86eoDgu9puYfb036wwTT536OlodWWqRIqlYyQOS5h+
            KURvuQkH7CT30swTun11hHibNomxPd97D49aYqr86vrNKYRrVWuruc3OO9ofFaWO
            hRuLVivLiuGfFMtkVun2V9ropRArHeSOHPfyCUETJIcyrKPxk7ack0U/Nq9uf3Rd
            z9iImQkqMSMvaYmsqIM5qjgMqU+aXfj98l1v0hYvAQKBgQDzoC23vjx01as1BVIA
            Z0fc5t+LSonhrKphHnHxxUx7pcmS5HrBCL4Rv+6HL15zCfTkYdt5w+6hByJMpDL4
            ZwrdyoI1fL21PSo/TdzNLtgB6FUtYqrUSSFAG3fLN2OYqDW5vxumsFwjn1YmKG1f
            emTjNE422oQv/xVsjmj7tgc9CQKBgQDrTOjTVChO/H7WgV20TM8/fg9XD4mfimhD
            g9apKReOtKniBL0sFcJH7XpDoNahPRhk+iDY16IbLknstnxGRml+Y63ZHbnD+1v6
            vdR15vjJECWHdn8u1y9FqOWa4oXAOO4G1q1FQmjXEIX8svyXSkX65Qg3w9h5oYpN
            nhPHVJenAwKBgQDsCOmiVq5uJ8GLSg9LksTeMdStOFdkDQy5sWyF6DiUp2gnaDPC
            J/02ZzTrRqqEXEYmquSgEYN2AdpqVL+JSRQPFC+ZMLUADjWLRZ3CMTtYhcdYhHqr
            1/peCP7EJXLaKUZ8IrrggYeTf8FQkOR+l699LWUF4iol8kbIeSUfkhlrOQKBgQC2
            H7NeTxdb+6eZFEyZD5KiTEpHUqltKU4GY/c0u6+WL1QGszBQ/Q6BadhmnAlEh+tn
            zQq7jDvW2f8yDxUlt75Tq4eWM6HjhZzt+RyHnZ0W0z6ZGSjb8oaOXmpJdeecnvPt
            qyA2KW7Id+udalSELWL5DWlM8HOPwW8xIJeig2FWTQKBgBkGMD+32aXltymx0SIo
            JVfL+kPBtPyDdAJbxJu8fFfhzbFGlLI5qVQnrzjgjhnkHcnvmTu2ZgPStArpJqUk
            4KNl3HZLG6vreo137aKjXzshdNwx1Yzw0PigLAwLgx7APFZYkM0qpE0JPyFeFORu
            XXDWlzK1YYlKSBuSsm9VWfXq
            -----END PRIVATE KEY-----
            """;

    // openssl req -out cert.pem -nodes -keyout private.key
    //   -newkey ec:<(openssl ecparam -name secp224r1) -new -x509
    private static final String EC_CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIIBvjCCAWygAwIBAgIJAK/rmJC9QdjcMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
            AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
            aXRzIFB0eSBMdGQwHhcNMTcwNzE0MTgxNjU2WhcNMTcwODEzMTgxNjU2WjBFMQsw
            CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
            ZXQgV2lkZ2l0cyBQdHkgTHRkME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEY83DklF/
            qOPmJkASvf25MaDvzF7w+MeYaBZHiC18y9mayfAcKPti4MbPR6ADAo9NxKbdsZjA
            13+jUDBOMB0GA1UdDgQWBBQxUP7SZIeKaQmFaAIBDRCJjUcXbzAfBgNVHSMEGDAW
            gBQxUP7SZIeKaQmFaAIBDRCJjUcXbzAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMC
            A0AAMD0CHCR7SmBxeufWpfAECH+Zp/2NMhhyIuYoeOThi3wCHQCyJmYQs8xHzC17
            yMyZj8YGfSSXgdWkp381P0gl
            -----END CERTIFICATE-----
            """;

    private static final String EC_PRIVATE_KEY = """
            -----BEGIN PRIVATE KEY-----
            MHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBz+XVZZoypybMtDZWBVcrPu
            IiVn3yZ+kzF+f2NyoTwDOgAEY83DklF/qOPmJkASvf25MaDvzF7w+MeYaBZHiC18
            y9mayfAcKPti4MbPR6ADAo9NxKbdsZjA138=
            -----END PRIVATE KEY-----
            """;

    @Test
    void invalidCert() {
        assertThatThrownBy(() -> new KeyWithCert(KEY, PASSWORD, INVALID_CERT))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void keyMismatch() {
        assertThatThrownBy(() -> new KeyWithCert(KEY, "", OPEN_SSL_CERT))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void validCert() throws CertificateException {
        assertThat(new KeyWithCert(ENCRYPTED_KEY, PASSWORD, GOOD_CERT)).isNotNull();
    }

    @Test
    void ellipticCurve() throws CertificateException {
        assertThat(new KeyWithCert(EC_PRIVATE_KEY, "", EC_CERTIFICATE)).isNotNull();
    }

    @Test
    void embeddedPrivateKey() throws CertificateException {
        assertThat(new KeyWithCert(OPEN_SSL_PRIVATE_KEY, "", OPEN_SSL_CERT)).isNotNull();
    }

    @Test
    void certOnly() throws CertificateException {
        assertThat(new KeyWithCert(GOOD_CERT))
                .isNotNull()
                .extracting(KeyWithCert::getCertificate)
                .isNotNull();
    }
}
