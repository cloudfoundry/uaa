package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.*;

import javax.net.ssl.KeyManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class SamlKeyManagerFactoryTests {

    public static final String legacyKey = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5
            L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA
            fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB
            AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges
            7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu
            lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp
            ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX
            kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL
            gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK
            vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe
            A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS
            N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB
            qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/
            -----END RSA PRIVATE KEY-----""";
    public static final String legacyPassphrase = "password";
    public static final String legacyCertificate = """
            -----BEGIN CERTIFICATE-----
            MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO
            MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO
            MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h
            cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx
            CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM
            BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb
            BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN
            ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W
            qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw
            znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha
            MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc
            gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD
            VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD
            VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh
            QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ
            0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC
            KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK
            RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
            -----END CERTIFICATE-----""";

    public static final String key1 = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEogIBAAKCAQEArRkvkddLUoNyuvu0ktkcLL0CyGG8Drh9oPsaVOLVHJqB1Ebr
            oNMTPbY0HPjuD5WBDZTi3ftNLp1mPn9wFy6FhMTvIYeQmTskH8m/kyVReXG/zfWq
            a4+V6UW4nmUcvfF3YNrHvN5VPTWTJrc2KBzseWQ70OaBNfBi6z4XbdOF45dDfck2
            oRnasinUv+rG+PUl7x8OjgdVyyen6qeCQ6xt8W9fHg//Nydlfwb3/L+syPoBujdu
            Hai7GoLUzm/zqOM9dhlR5mjuEJ3QUvnmGKrGDoeHFog0CMgLC+C0Z4ZANB6GbjlM
            bsQczsaYxHMqAMOnOe6xIXUrPOoc7rclwZeHMQIDAQABAoIBAAFB2ZKZmbZztfWd
            tmYKpaW9ibOi4hbJSEBPEpXjP+EBTkgYa8WzQsSD+kTrme8LCvDqT+uE076u7fsu
            OcYxVE7ujz4TGf3C7DQ+5uFOuBTFurroOeCmHlSfaQPdgCPxCQjvDdxVUREsvnDd
            i8smyqDnFXgi9HVL1awXu1vU2XgZshfl6wBOCNomVMCN8mVcBQ0KM88SUvoUwM7i
            sSdj1yQV16Za8+nVnMW41FMHegVRd3Y5EsXJfwGuXnZMIG87PavH1nUqn9NOFq9Y
            kb4SeOO47PaMxv7jMaXltVVokdGH8L/BY4we8tBL+wVeUJ94aYx/Q/LUAtRPbKPS
            ZSEi/7ECgYEA3dUg8DXzo59zl5a8kfz3aoLl8RqRYzuf8F396IuiVcqYlwlWOkZW
            javwviEOEdZhUZPxK1duXKTvYw7s6eDFwV+CklTZu4A8M3Os0D8bSL/pIKqcadt5
            JClIRmOmmQpj9AYhSdBTdQtJGjVDaDXJBb7902pDm9I4jMFbjAKLZNsCgYEAx8J3
            Y1c7GwHw6dxvTywrw3U6z1ILbx2olVLY6DIgZaMVT4EKTAv2Ke4xF4OZYG+lLRbt
            hhOHYzRMYC38MNl/9RXHBgUlQJXOQb9u644motl5dcMvzIIuWFCn5vXxR2C3McNy
            vPdzYS2M64xRGy+IENtPSCcUs9C99bEajRcuG+MCgYAONabEfFA8/OvEnA08NL4M
            fpIIHbGOb7VRClRHXxpo8G9RzXFOjk7hCFCFfUyPa/IT7awXIKSbHp2O9NfMK2+/
            cUTF5tWDozU3/oLlXAV9ZX2jcApQ5ZQe8t4EVEHJr9azPOlI9yVBbBWkriDBPiDA
            U3mi3z2xb4fbzE726vrO3QKBgA6PfTZPgG5qiM3zFGX3+USpAd1kxJKX3dbskAT0
            ymm+JmqCJGcApDPQOeHV5NMjsC2GM1AHkmHHyR1lnLFO2UXbDYPB0kJP6RXfx00C
            MozCP1k3Hf/RKWGkl2h9WtXyFchZz744Zz+ZG2F7+9l4cHmSEshWmOq2d3I2M5I/
            M0wzAoGAa2oM4Q6n+FMHl9e8H+2O4Dgm7wAdhuZI1LhnLL6GLVC1JTmGrz/6G2TX
            iNFhc0lnDcVeZlwg4i7M7MH8UFdWj3ZEylsXjrjIspuAJg7a/6qmP9s2ITVffqYk
            2slwG2SIQchM5/0uOiP9W0YIjYEe7hgHUmL9Rh8xFuo9y72GH8c=
            -----END RSA PRIVATE KEY-----""";
    public static final String passphrase1 = "password";
    public static final String certificate1 = """
            -----BEGIN CERTIFICATE-----
            MIID0DCCArgCCQDBRxU0ucjw6DANBgkqhkiG9w0BAQsFADCBqTELMAkGA1UEBhMC
            VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR8wHQYDVQQK
            ExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVLZXkgMTEiMCAGA1UE
            AxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqGSIb3DQEJARYRZmhh
            bmlrQHBpdm90YWwuaW8wHhcNMTcwNDEwMTkxMTIyWhcNMTgwNDEwMTkxMTIyWjCB
            qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
            c2NvMR8wHQYDVQQKExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVL
            ZXkgMTEiMCAGA1UEAxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqG
            SIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IB
            DwAwggEKAoIBAQCtGS+R10tSg3K6+7SS2RwsvQLIYbwOuH2g+xpU4tUcmoHURuug
            0xM9tjQc+O4PlYENlOLd+00unWY+f3AXLoWExO8hh5CZOyQfyb+TJVF5cb/N9apr
            j5XpRbieZRy98Xdg2se83lU9NZMmtzYoHOx5ZDvQ5oE18GLrPhdt04Xjl0N9yTah
            GdqyKdS/6sb49SXvHw6OB1XLJ6fqp4JDrG3xb18eD/83J2V/Bvf8v6zI+gG6N24d
            qLsagtTOb/Oo4z12GVHmaO4QndBS+eYYqsYOh4cWiDQIyAsL4LRnhkA0HoZuOUxu
            xBzOxpjEcyoAw6c57rEhdSs86hzutyXBl4cxAgMBAAEwDQYJKoZIhvcNAQELBQAD
            ggEBAB72QKF9Iri+UdCGAIok/qIeKw5AwZ0wtiONa+DF4B80/yAA1ObpuO3eeeka
            t0s4wtCRflE08zLrwqHlvKQAGKmJkfRLfEqfKStIUOTHQxE6wOaBtfW41M9ZF1hX
            NHpnkfmSQjaHVNTRbABiFH6eTq8J6CuO12PyDf7lW3EofvcTU3ulsDhuMAz02ypJ
            BgcOufnl+qP/m/BhVQsRD5mtJ56uJpHvri1VR2kj8N59V8f6KPO2m5Q6MulEhWml
            TsxyxUl03oyICDP1cbpYtDk2VddVNWipHHPH/mBVW41EBVv0VDV03LH3RfS9dXiK
            ynuP3shhqhFvaaiUTZP4l5yF/GQ=
            -----END CERTIFICATE-----""";

    public static final String key2 = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEAwt7buITRZhXX98apcgJbiHhrPkrgn5MCsCphRQ89oWPUHWjN
            j9Kz2m9LaKgq9DnNLl22U4e6/LUQToBCLxkIqwaobZKjIUjNAmNomqbNO7AD2+K7
            RCiQ2qijWUwXGu+5+fSmF/MOermNKUDiQnRJSSSAPObAHOI980zTWVsApKpcFVaV
            vk/299L/0rk8I/mNvf63cdw4Nh3xn4Ct+oCnTaDg5OtpGz8sHlocOAti+LdrtNzH
            uBWq8q2sdhFQBRGe1MOeH8CAEHgKYwELTBCJEyLhykdRgxXJHSaL56+mb6HQvGO/
            oyZHn+qHsCCjcdR1L/U4qt4m7HBimv0qbvApQwIDAQABAoIBAQCftmmcnHbG1WZR
            NChSQa5ldlRnFJVvE90jJ0jbgfdAHAKQLAI2Ozme8JJ8bz/tNKZ+tt2lLlxJm9iG
            jkYwNbNOAMHwNDuxHuqvZ2wnPEh+/+7Zu8VBwoGeRJLEsEFLmWjyfNnYTSPz37nb
            Mst+LbKW2OylfXW89oxRqQibdqNbULpcU4NBDkMjToH1Z4dUFx3X2R2AAwgDz4Ku
            HN4HoxbsbUCI5wLDJrTGrJgEntMSdsSdOY48YOMBnHqqfw7KoJ0sGjrPUy0vOGq2
            CeP3uqbXX/mJpvJ+jg3Y2b1Zeu2I+vAnZrxlaZ+hYnZfoNqVjBZ/EEq/lmEovMvr
            erP8FYI5AoGBAOrlmMZYdhW0fRzfpx6WiBJUkFfmit4qs9nQRCouv+jHS5QL9aM9
            c+iKeP6kWuxBUYaDBmf5J1OBW4omNd384NX5PCiL/Fs/lxgdMZqEhnhT4Dj4Q6m6
            ZXUuY6hamoF5+z2mtkZzRyvD1LUAARKJw6ggUtcH28cYC3RkZ5P6SWHVAoGBANRg
            scI9pF2VUrmwpgIGhynLBEO26k8j/FyE3S7lPcUZdgPCUZB0/tGklSo183KT/KQY
            TgO2mqb8a8xKCz41DTnUPqJWZzBOFw5QaD2i9O6soXUAKqaUm3g40/gyWX1hUtHa
            K0Kw5z1Sf3MoCpW0Ozzn3znYbAoSvBRr53d0EVK3AoGAOD1ObbbCVwIGroIR1i3+
            WD0s7g7Bkt2wf+bwWxUkV4xX2RNf9XyCItv8iiM5rbUZ2tXGE+DAfKrNCu+JGCQy
            hKiOsbqKaiJ4f4qF1NQECg0y8xDlyl5Zakv4ClffBD77W1Bt9cIl+SGC7O8aUqDv
            WnKawucbxLhKDcz4S6KyLR0CgYEAhuRrw24XqgEgLCVRK9QtoZP7P28838uBjNov
            Cow8caY8WSLhX5mQCGQ7AjaGTG5Gd4ugcadYD1wgs/8LqRVVMzfmGII8xGe1KThV
            HWEVpUssuf3DGU8meHPP3sNMJ+DbE8M42wE1vrNZlDEImBGD1qmIFVurM7K2l1n6
            CNtF7X0CgYBuFf0A0cna8LnxOAPm8EPHgFq4TnDU7BJzzcO/nsORDcrh+dZyGJNS
            fUTMp4k+AQCm9UwJAiSf4VUwCbhXUZ3S+xB55vrH+Yc2OMtsIYhzr3OCkbgKBMDn
            nBVKSGAomYD2kCUmSbg7bUrFfGntmvOLqTHtVfrCyE5i8qS63RbHlA==
            -----END RSA PRIVATE KEY-----""";
    public static final String passphrase2 = "password";
    public static final String certificate2 = """
            -----BEGIN CERTIFICATE-----
            MIID0DCCArgCCQDqnPTUvA17+TANBgkqhkiG9w0BAQsFADCBqTELMAkGA1UEBhMC
            VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR8wHQYDVQQK
            ExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVLZXkgMjEiMCAGA1UE
            AxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqGSIb3DQEJARYRZmhh
            bmlrQHBpdm90YWwuaW8wHhcNMTcwNDEwMTkxNTAyWhcNMTgwNDEwMTkxNTAyWjCB
            qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
            c2NvMR8wHQYDVQQKExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVL
            ZXkgMjEiMCAGA1UEAxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqG
            SIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IB
            DwAwggEKAoIBAQDC3tu4hNFmFdf3xqlyAluIeGs+SuCfkwKwKmFFDz2hY9QdaM2P
            0rPab0toqCr0Oc0uXbZTh7r8tRBOgEIvGQirBqhtkqMhSM0CY2iaps07sAPb4rtE
            KJDaqKNZTBca77n59KYX8w56uY0pQOJCdElJJIA85sAc4j3zTNNZWwCkqlwVVpW+
            T/b30v/SuTwj+Y29/rdx3Dg2HfGfgK36gKdNoODk62kbPyweWhw4C2L4t2u03Me4
            Faryrax2EVAFEZ7Uw54fwIAQeApjAQtMEIkTIuHKR1GDFckdJovnr6ZvodC8Y7+j
            Jkef6oewIKNx1HUv9Tiq3ibscGKa/Spu8ClDAgMBAAEwDQYJKoZIhvcNAQELBQAD
            ggEBAKzeh/bRDEEP/WGsiYhCCfvESyt0QeKwUk+Hfl0/oP4m9pXNrnMRApyoi7FB
            owpmXIeqDqGigPai6pJ3xCO94P+Bz7WTk0+jScYm/hGpcIOeKh8FBfW0Fddu9Otn
            qVk0FdRSCTjUZKQlNOqVTjBeKOjHmTkgh96IR3EP2/hp8Ym4HLC+w265V7LnkqD2
            SoMez7b2V4NmN7z9OxTALUbTzmFG77bBDExHvfbiFlkIptx8+IloJOCzUsPEg6Ur
            kueuR7IB1S4q6Ja7Gb9b9NYQDFt4hjb5mC9aPxaX+KK2JlZg4cTFVCdkIyp2/fHI
            iQpMzNWb7zZWlCfDL4dJZHYoNfg=
            -----END CERTIFICATE-----""";

    private SamlKeyManagerFactory samlKeyManagerFactory;
    private SamlConfig config;

    @BeforeAll
    static void addBCProvider() {
        try {
            Security.addProvider(new BouncyCastleFipsProvider());
        } catch (SecurityException e) {
            e.printStackTrace();
            System.err.println("Ignoring provider error, may already be added.");
        }
    }

    @BeforeEach
    void setup() {
        samlKeyManagerFactory = new SamlKeyManagerFactory();

        IdentityZoneHolder.clear();
        config = new SamlConfig();
        config.setPrivateKey(legacyKey);
        config.setCertificate(legacyCertificate);
        config.setPrivateKeyPassword(legacyPassphrase);

        config.addKey("key-1", new SamlKey(key1, passphrase1, certificate1));
        config.addKey("key-2", new SamlKey(key2, passphrase2, certificate2));
    }

    @AfterEach
    void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void multipleKeysLegacyIsActiveKey() {
        String alias = SamlConfig.LEGACY_KEY_ID;
//        KeyManager manager = samlKeyManagerFactory.getKeyManager(config);
//        assertEquals(alias, manager.getDefaultCredentialName());
//        assertEquals(3, manager.getAvailableCredentials().size());
//        assertThat(manager.getAvailableCredentials(), containsInAnyOrder(SamlConfig.LEGACY_KEY_ID, "key-1", "key-2"));
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void multipleKeysWithActiveKey() {
        config.setActiveKeyId("key-1");
        String alias = "key-1";
//        JKSKeyManager manager = (JKSKeyManager) samlKeyManagerFactory.getKeyManager(config);
//        assertEquals(alias, manager.getDefaultCredentialName());
//        assertEquals(3, manager.getAvailableCredentials().size());
//        assertThat(manager.getAvailableCredentials(), containsInAnyOrder(SamlConfig.LEGACY_KEY_ID + "", "key-1", "key-2"));
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void addActiveKey() {
        config.addAndActivateKey("key-3", new SamlKey(key1, passphrase1, certificate1));
        String alias = "key-3";
//        JKSKeyManager manager = (JKSKeyManager) samlKeyManagerFactory.getKeyManager(config);
//        assertEquals(alias, manager.getDefaultCredentialName());
//        assertEquals(4, manager.getAvailableCredentials().size());
//        assertThat(manager.getAvailableCredentials(), containsInAnyOrder(SamlConfig.LEGACY_KEY_ID, "key-1", "key-2", alias));
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void multipleKeysWithActiveKeyInOtherZone() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("other-zone-id", "domain"));
        config.setActiveKeyId("key-1");
        String alias = "key-1";
//        JKSKeyManager manager = (JKSKeyManager) samlKeyManagerFactory.getKeyManager(config);
//        assertEquals(alias, manager.getDefaultCredentialName());
//        assertEquals(3, manager.getAvailableCredentials().size());
//        assertThat(manager.getAvailableCredentials(), containsInAnyOrder(SamlConfig.LEGACY_KEY_ID, "key-1", "key-2"));
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void keystoreImplsIsNotASingleton() throws KeyStoreException {
        assertThat(KeyStore.getInstance("JKS")).isNotSameAs(KeyStore.getInstance("JKS"));
//        JKSKeyManager manager1 = (JKSKeyManager) samlKeyManagerFactory.getKeyManager(config);
        config.setKeys(new HashMap<>());
        config.setPrivateKey(key1);
        config.setPrivateKeyPassword("password");
        config.setCertificate(certificate1);

//        JKSKeyManager manager2 = (JKSKeyManager) samlKeyManagerFactory.getKeyManager(config);
//        KeyStore ks1 = (KeyStore) ReflectionTestUtils.getField(manager1, JKSKeyManager.class, "keyStore");
//        KeyStore ks2 = (KeyStore) ReflectionTestUtils.getField(manager2, JKSKeyManager.class, "keyStore");

        String alias = SamlConfig.LEGACY_KEY_ID;

//        assertNotEquals(ks1.getCertificate(alias), ks2.getCertificate(alias));
//        assertEquals(ks1.getCertificate(alias), ks1.getCertificate(alias));
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void testAddCertsKeysOnly() {
        config.setKeys(new HashMap<>());
        config.addAndActivateKey("cert-only", new SamlKey(null, null, certificate1));
//        JKSKeyManager manager1 = (JKSKeyManager) samlKeyManagerFactory.getKeyManager(config);
//        assertNotNull(manager1.getDefaultCredential().getPublicKey());
//        assertNull(manager1.getDefaultCredential().getPrivateKey());
    }
}
