/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GeneralIdentityZoneConfigurationValidatorTests {

    public static Stream<IdentityZoneValidator.Mode> parameters() {
        return Stream.of(IdentityZoneValidator.Mode.CREATE, IdentityZoneValidator.Mode.MODIFY);
    }

    private static final String LEGACY_KEY = """
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

    private static final String LEGACY_PASSPHRASE = "password";

    private static final String LEGACY_CERTIFICATE = """
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

    private static final String KEY_1 = """
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

    private static final String PASSPHRASE_1 = "password";

    private static final String CERTIFICATE_1 = """
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

    private static final String KEY_2 = """
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

    private static final String PASSPHRASE_2 = "password";

    private static final String CERTIFICATE_2 = """
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

    SamlConfig samlConfig;

    @BeforeAll
    static void addBCProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    GeneralIdentityZoneConfigurationValidator validator;
    IdentityZone zone;

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.clear();
        samlConfig = new SamlConfig();
        samlConfig.setPrivateKey(LEGACY_KEY);
        samlConfig.setCertificate(LEGACY_CERTIFICATE);
        samlConfig.setPrivateKeyPassword(LEGACY_PASSPHRASE);
        samlConfig.addKey("key-1", new SamlKey(KEY_1, PASSPHRASE_1, CERTIFICATE_1));
        samlConfig.addKey("key-2", new SamlKey(KEY_2, PASSPHRASE_2, CERTIFICATE_2));
        validator = new GeneralIdentityZoneConfigurationValidator();
        IdentityZoneConfiguration zoneConfiguration = new IdentityZoneConfiguration();
        BrandingInformation brandingInformation = new BrandingInformation();
        zoneConfiguration.setBranding(brandingInformation);
        zoneConfiguration.setSamlConfig(samlConfig);

        zone = new IdentityZone();
        zone.setConfig(zoneConfiguration);
        IdentityZoneHolder.clear();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_with_legacy_key_active(IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        validator.validate(zone, mode);
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_with_invalid_active_key_id(IdentityZoneValidator.Mode mode) {
        samlConfig.setActiveKeyId("wrong");
        assertThatThrownBy(() ->
                validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid SAML active key ID: 'wrong'. Couldn't find any matching keys.");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_with_invalid_consent_link(IdentityZoneValidator.Mode mode) {
        zone.getConfig().getBranding().setConsent(new Consent("some text", "some-invalid-link"));
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid consent link: some-invalid-link. Must be a properly formatted URI beginning with http:// or https://");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validateConsent_withNotNullTextAndNullLink(IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        zone.getConfig().getBranding().setConsent(new Consent("Terms and Conditions", null));
        validator.validate(zone, mode);
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validateConsent_withNullTextAndNotNullLink(IdentityZoneValidator.Mode mode) {
        zone.getConfig().getBranding().setConsent(new Consent(null, "http://example.com"));
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Consent text must be set if configuring consent");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validateConsent_withNullTextAndNullLink(IdentityZoneValidator.Mode mode) {
        zone.getConfig().getBranding().setConsent(new Consent());
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Consent text must be set if configuring consent");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_without_legacy_key(IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        samlConfig.setKeys(emptyMap());
        assertThat(samlConfig.getActiveKeyId()).isNull();
        samlConfig.addKey("key-1", new SamlKey(KEY_1, PASSPHRASE_1, CERTIFICATE_1));
        samlConfig.addAndActivateKey("key-2", new SamlKey(KEY_2, PASSPHRASE_2, CERTIFICATE_2));
        validator.validate(zone, mode);
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_without_legacy_key_and_null_active_key(IdentityZoneValidator.Mode mode) {
        samlConfig.setKeys(emptyMap());
        assertThat(samlConfig.getActiveKeyId()).isNull();
        samlConfig.addKey("key-1", new SamlKey(KEY_1, PASSPHRASE_1, CERTIFICATE_1));
        samlConfig.addKey("key-2", new SamlKey(KEY_2, PASSPHRASE_2, CERTIFICATE_2));
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid SAML active key ID: 'null'. Couldn't find any matching keys.");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_no_keys(IdentityZoneValidator.Mode mode) throws Exception {
        samlConfig.setKeys(emptyMap());
        assertThat(samlConfig.getActiveKeyId()).isNull();
        validator.validate(zone, mode);
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_isser_no_keys(IdentityZoneValidator.Mode mode) {
        samlConfig.setKeys(emptyMap());
        zone.getConfig().setIssuer("http://localhost/new");
        assertThat(samlConfig.getActiveKeyId()).isNull();
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("You cannot set issuer value unless you have set your own signing key for this identity zone.");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_invalid_corsPolicy_xhrConfiguration_allowedUris(IdentityZoneValidator.Mode mode) {
        List<String> invalidAllowedUris = List.of("https://google.com", "https://*.example.com", "^/uaa/userinfo(", "^/uaa/logout.do$");
        zone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedUris(invalidAllowedUris);
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid value in config.corsPolicy.xhrConfiguration.allowedUris: '^/uaa/userinfo('");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_invalid_corsPolicy_xhrConfiguration_allowedOrigins(IdentityZoneValidator.Mode mode) {
        List<String> invalidOrigins = List.of("https://google.com", "https://*.example.com", "^/uaa/userinfo(", "^/uaa/logout.do$");
        zone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedOrigins(invalidOrigins);
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid value in config.corsPolicy.xhrConfiguration.allowedOrigins: '^/uaa/userinfo('");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_invalid_corsPolicy_defaultConfiguration_allowedUris(IdentityZoneValidator.Mode mode) {
        List<String> invalidAllowedUris = List.of("https://google.com", "https://*.example.com", "^/uaa/userinfo(", "^/uaa/logout.do$");
        zone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedUris(invalidAllowedUris);
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid value in config.corsPolicy.defaultConfiguration.allowedUris: '^/uaa/userinfo('");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_invalid_corsPolicy_defaultConfiguration_allowedOrigins(IdentityZoneValidator.Mode mode) {
        List<String> invalidOrigins = List.of("https://google.com", "https://*.example.com", "^/uaa/userinfo(", "^/uaa/logout.do$");
        zone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedOrigins(invalidOrigins);
        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                .hasMessageContaining("Invalid value in config.corsPolicy.defaultConfiguration.allowedOrigins: '^/uaa/userinfo('");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_with_token_key_and_certificate(IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        setupTokenPolicyWithCertificate(LEGACY_KEY, LEGACY_CERTIFICATE, "RS256");

        IdentityZoneConfiguration identityZoneConfiguration = validator.validate(zone, mode);
        Map<String, TokenPolicy.KeyInformation> keys = identityZoneConfiguration.getTokenPolicy().getKeys();
        assertThat(keys.get("id-1").getSigningKey()).isEqualTo(LEGACY_KEY);
        assertThat(keys.get("id-1").getSigningCert()).isEqualTo(LEGACY_CERTIFICATE);
        assertThat(keys.get("id-1").getSigningAlg()).isEqualTo("RS256");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void validate_with_token_key_without_certificate(IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        setupTokenPolicyWithCertificate("secretkey", null, "HS512");

        IdentityZoneConfiguration identityZoneConfiguration = validator.validate(zone, mode);
        Map<String, TokenPolicy.KeyInformation> keys = identityZoneConfiguration.getTokenPolicy().getKeys();
        assertThat(keys.get("id-1").getSigningKey()).isEqualTo("secretkey");
        assertThat(keys.get("id-1").getSigningCert()).isNull();
        assertThat(keys.get("id-1").getSigningAlg()).isEqualTo("HS512");
    }

    private void setupTokenPolicyWithCertificate(String privateKey, String certificate, String alg) {
        Map<String, TokenPolicy.KeyInformation> keyInformationMap = new HashMap<>();
        TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
        keyInformation.setSigningKey(privateKey);
        keyInformation.setSigningCert(certificate);
        keyInformation.setSigningAlg(alg);
        keyInformationMap.put("id-1", keyInformation);
        zone.getConfig().getTokenPolicy().setKeyInformation(keyInformationMap);
        zone.getConfig().getTokenPolicy().setActiveKeyId("id-1");
    }
}
