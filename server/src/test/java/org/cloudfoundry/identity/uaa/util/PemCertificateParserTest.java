package org.cloudfoundry.identity.uaa.util;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PemCertificateParserTest {

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    // openssl req -out cert.pem -nodes -keyout private.key -newkey rsa:2048 -new -x509
    private static final String VALID_CERT = """
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

    private static final String MALFORMED_CERT = """
            -----BEGIN CERTIFICATE-----
            FILIPMIIEJTCCA46gAwIBAgIJANIqfxWTfhpkMA0GCSqGSIb3DQEBBQUAMIG+MQswCQYD
            VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5j
            aXNjbzEdMBsGA1UEChMUUGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Ns
            b3VkIEZvdW5kcnkgSWRlbnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2Yt
            YXBwLmNvbTEfMB0GCSqGSIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzAeFw0xNTA1
            MTQxNzE5MTBaFw0yNTA1MTExNzE5MTBaMIG+MQswCQYDVQQGEwJVUzETMBEGA1UE
            -----END CERTIFICATE-----
            """;

    @Test
    void parseCertificate_validPem_returnsCertificate() {
        X509Certificate certificate = PemCertificateParser.parseCertificate(VALID_CERT);
        assertThat(certificate).isNotNull();
    }

    @Test
    void parseCertificate_malformedPem_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> PemCertificateParser.parseCertificate(MALFORMED_CERT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseCertificate_notACertificate_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> PemCertificateParser.parseCertificate("not a pem certificate"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void parseCertificates_nullOrEmpty_returnsEmptyList(List<String> input) {
        assertThat(PemCertificateParser.parseCertificates(input)).isEmpty();
    }

    @Test
    void parseCertificates_allValid_returnsAllCertificates() {
        List<X509Certificate> certificates = PemCertificateParser.parseCertificates(List.of(VALID_CERT, VALID_CERT));
        assertThat(certificates).hasSize(2);
    }

    @Test
    void parseCertificates_oneMalformedEntry_throwsWithIndexInMessage() {
        assertThatThrownBy(() -> PemCertificateParser.parseCertificates(List.of(VALID_CERT, MALFORMED_CERT)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("index 1");
    }
}
