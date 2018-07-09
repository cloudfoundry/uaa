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

package org.cloudfoundry.identity.uaa.saml;

public class SamlTestKeys {
    public static final String legacyKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
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
        "-----END RSA PRIVATE KEY-----";
    public static final String legacyPassphrase = "password";
    public static final String legacyCertificate = "-----BEGIN CERTIFICATE-----\n" +
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
        "-----END CERTIFICATE-----";

    public static final String key1 = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEogIBAAKCAQEArRkvkddLUoNyuvu0ktkcLL0CyGG8Drh9oPsaVOLVHJqB1Ebr\n" +
        "oNMTPbY0HPjuD5WBDZTi3ftNLp1mPn9wFy6FhMTvIYeQmTskH8m/kyVReXG/zfWq\n" +
        "a4+V6UW4nmUcvfF3YNrHvN5VPTWTJrc2KBzseWQ70OaBNfBi6z4XbdOF45dDfck2\n" +
        "oRnasinUv+rG+PUl7x8OjgdVyyen6qeCQ6xt8W9fHg//Nydlfwb3/L+syPoBujdu\n" +
        "Hai7GoLUzm/zqOM9dhlR5mjuEJ3QUvnmGKrGDoeHFog0CMgLC+C0Z4ZANB6GbjlM\n" +
        "bsQczsaYxHMqAMOnOe6xIXUrPOoc7rclwZeHMQIDAQABAoIBAAFB2ZKZmbZztfWd\n" +
        "tmYKpaW9ibOi4hbJSEBPEpXjP+EBTkgYa8WzQsSD+kTrme8LCvDqT+uE076u7fsu\n" +
        "OcYxVE7ujz4TGf3C7DQ+5uFOuBTFurroOeCmHlSfaQPdgCPxCQjvDdxVUREsvnDd\n" +
        "i8smyqDnFXgi9HVL1awXu1vU2XgZshfl6wBOCNomVMCN8mVcBQ0KM88SUvoUwM7i\n" +
        "sSdj1yQV16Za8+nVnMW41FMHegVRd3Y5EsXJfwGuXnZMIG87PavH1nUqn9NOFq9Y\n" +
        "kb4SeOO47PaMxv7jMaXltVVokdGH8L/BY4we8tBL+wVeUJ94aYx/Q/LUAtRPbKPS\n" +
        "ZSEi/7ECgYEA3dUg8DXzo59zl5a8kfz3aoLl8RqRYzuf8F396IuiVcqYlwlWOkZW\n" +
        "javwviEOEdZhUZPxK1duXKTvYw7s6eDFwV+CklTZu4A8M3Os0D8bSL/pIKqcadt5\n" +
        "JClIRmOmmQpj9AYhSdBTdQtJGjVDaDXJBb7902pDm9I4jMFbjAKLZNsCgYEAx8J3\n" +
        "Y1c7GwHw6dxvTywrw3U6z1ILbx2olVLY6DIgZaMVT4EKTAv2Ke4xF4OZYG+lLRbt\n" +
        "hhOHYzRMYC38MNl/9RXHBgUlQJXOQb9u644motl5dcMvzIIuWFCn5vXxR2C3McNy\n" +
        "vPdzYS2M64xRGy+IENtPSCcUs9C99bEajRcuG+MCgYAONabEfFA8/OvEnA08NL4M\n" +
        "fpIIHbGOb7VRClRHXxpo8G9RzXFOjk7hCFCFfUyPa/IT7awXIKSbHp2O9NfMK2+/\n" +
        "cUTF5tWDozU3/oLlXAV9ZX2jcApQ5ZQe8t4EVEHJr9azPOlI9yVBbBWkriDBPiDA\n" +
        "U3mi3z2xb4fbzE726vrO3QKBgA6PfTZPgG5qiM3zFGX3+USpAd1kxJKX3dbskAT0\n" +
        "ymm+JmqCJGcApDPQOeHV5NMjsC2GM1AHkmHHyR1lnLFO2UXbDYPB0kJP6RXfx00C\n" +
        "MozCP1k3Hf/RKWGkl2h9WtXyFchZz744Zz+ZG2F7+9l4cHmSEshWmOq2d3I2M5I/\n" +
        "M0wzAoGAa2oM4Q6n+FMHl9e8H+2O4Dgm7wAdhuZI1LhnLL6GLVC1JTmGrz/6G2TX\n" +
        "iNFhc0lnDcVeZlwg4i7M7MH8UFdWj3ZEylsXjrjIspuAJg7a/6qmP9s2ITVffqYk\n" +
        "2slwG2SIQchM5/0uOiP9W0YIjYEe7hgHUmL9Rh8xFuo9y72GH8c=\n" +
        "-----END RSA PRIVATE KEY-----";
    public static final String passphrase1 = "password";
    public static final String certificate1 = "-----BEGIN CERTIFICATE-----\n" +
        "MIID0DCCArgCCQDBRxU0ucjw6DANBgkqhkiG9w0BAQsFADCBqTELMAkGA1UEBhMC\n" +
        "VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR8wHQYDVQQK\n" +
        "ExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVLZXkgMTEiMCAGA1UE\n" +
        "AxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqGSIb3DQEJARYRZmhh\n" +
        "bmlrQHBpdm90YWwuaW8wHhcNMTcwNDEwMTkxMTIyWhcNMTgwNDEwMTkxMTIyWjCB\n" +
        "qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\n" +
        "c2NvMR8wHQYDVQQKExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVL\n" +
        "ZXkgMTEiMCAGA1UEAxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqG\n" +
        "SIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
        "DwAwggEKAoIBAQCtGS+R10tSg3K6+7SS2RwsvQLIYbwOuH2g+xpU4tUcmoHURuug\n" +
        "0xM9tjQc+O4PlYENlOLd+00unWY+f3AXLoWExO8hh5CZOyQfyb+TJVF5cb/N9apr\n" +
        "j5XpRbieZRy98Xdg2se83lU9NZMmtzYoHOx5ZDvQ5oE18GLrPhdt04Xjl0N9yTah\n" +
        "GdqyKdS/6sb49SXvHw6OB1XLJ6fqp4JDrG3xb18eD/83J2V/Bvf8v6zI+gG6N24d\n" +
        "qLsagtTOb/Oo4z12GVHmaO4QndBS+eYYqsYOh4cWiDQIyAsL4LRnhkA0HoZuOUxu\n" +
        "xBzOxpjEcyoAw6c57rEhdSs86hzutyXBl4cxAgMBAAEwDQYJKoZIhvcNAQELBQAD\n" +
        "ggEBAB72QKF9Iri+UdCGAIok/qIeKw5AwZ0wtiONa+DF4B80/yAA1ObpuO3eeeka\n" +
        "t0s4wtCRflE08zLrwqHlvKQAGKmJkfRLfEqfKStIUOTHQxE6wOaBtfW41M9ZF1hX\n" +
        "NHpnkfmSQjaHVNTRbABiFH6eTq8J6CuO12PyDf7lW3EofvcTU3ulsDhuMAz02ypJ\n" +
        "BgcOufnl+qP/m/BhVQsRD5mtJ56uJpHvri1VR2kj8N59V8f6KPO2m5Q6MulEhWml\n" +
        "TsxyxUl03oyICDP1cbpYtDk2VddVNWipHHPH/mBVW41EBVv0VDV03LH3RfS9dXiK\n" +
        "ynuP3shhqhFvaaiUTZP4l5yF/GQ=\n" +
        "-----END CERTIFICATE-----";

    public static final String key2 = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEpAIBAAKCAQEAwt7buITRZhXX98apcgJbiHhrPkrgn5MCsCphRQ89oWPUHWjN\n" +
        "j9Kz2m9LaKgq9DnNLl22U4e6/LUQToBCLxkIqwaobZKjIUjNAmNomqbNO7AD2+K7\n" +
        "RCiQ2qijWUwXGu+5+fSmF/MOermNKUDiQnRJSSSAPObAHOI980zTWVsApKpcFVaV\n" +
        "vk/299L/0rk8I/mNvf63cdw4Nh3xn4Ct+oCnTaDg5OtpGz8sHlocOAti+LdrtNzH\n" +
        "uBWq8q2sdhFQBRGe1MOeH8CAEHgKYwELTBCJEyLhykdRgxXJHSaL56+mb6HQvGO/\n" +
        "oyZHn+qHsCCjcdR1L/U4qt4m7HBimv0qbvApQwIDAQABAoIBAQCftmmcnHbG1WZR\n" +
        "NChSQa5ldlRnFJVvE90jJ0jbgfdAHAKQLAI2Ozme8JJ8bz/tNKZ+tt2lLlxJm9iG\n" +
        "jkYwNbNOAMHwNDuxHuqvZ2wnPEh+/+7Zu8VBwoGeRJLEsEFLmWjyfNnYTSPz37nb\n" +
        "Mst+LbKW2OylfXW89oxRqQibdqNbULpcU4NBDkMjToH1Z4dUFx3X2R2AAwgDz4Ku\n" +
        "HN4HoxbsbUCI5wLDJrTGrJgEntMSdsSdOY48YOMBnHqqfw7KoJ0sGjrPUy0vOGq2\n" +
        "CeP3uqbXX/mJpvJ+jg3Y2b1Zeu2I+vAnZrxlaZ+hYnZfoNqVjBZ/EEq/lmEovMvr\n" +
        "erP8FYI5AoGBAOrlmMZYdhW0fRzfpx6WiBJUkFfmit4qs9nQRCouv+jHS5QL9aM9\n" +
        "c+iKeP6kWuxBUYaDBmf5J1OBW4omNd384NX5PCiL/Fs/lxgdMZqEhnhT4Dj4Q6m6\n" +
        "ZXUuY6hamoF5+z2mtkZzRyvD1LUAARKJw6ggUtcH28cYC3RkZ5P6SWHVAoGBANRg\n" +
        "scI9pF2VUrmwpgIGhynLBEO26k8j/FyE3S7lPcUZdgPCUZB0/tGklSo183KT/KQY\n" +
        "TgO2mqb8a8xKCz41DTnUPqJWZzBOFw5QaD2i9O6soXUAKqaUm3g40/gyWX1hUtHa\n" +
        "K0Kw5z1Sf3MoCpW0Ozzn3znYbAoSvBRr53d0EVK3AoGAOD1ObbbCVwIGroIR1i3+\n" +
        "WD0s7g7Bkt2wf+bwWxUkV4xX2RNf9XyCItv8iiM5rbUZ2tXGE+DAfKrNCu+JGCQy\n" +
        "hKiOsbqKaiJ4f4qF1NQECg0y8xDlyl5Zakv4ClffBD77W1Bt9cIl+SGC7O8aUqDv\n" +
        "WnKawucbxLhKDcz4S6KyLR0CgYEAhuRrw24XqgEgLCVRK9QtoZP7P28838uBjNov\n" +
        "Cow8caY8WSLhX5mQCGQ7AjaGTG5Gd4ugcadYD1wgs/8LqRVVMzfmGII8xGe1KThV\n" +
        "HWEVpUssuf3DGU8meHPP3sNMJ+DbE8M42wE1vrNZlDEImBGD1qmIFVurM7K2l1n6\n" +
        "CNtF7X0CgYBuFf0A0cna8LnxOAPm8EPHgFq4TnDU7BJzzcO/nsORDcrh+dZyGJNS\n" +
        "fUTMp4k+AQCm9UwJAiSf4VUwCbhXUZ3S+xB55vrH+Yc2OMtsIYhzr3OCkbgKBMDn\n" +
        "nBVKSGAomYD2kCUmSbg7bUrFfGntmvOLqTHtVfrCyE5i8qS63RbHlA==\n" +
        "-----END RSA PRIVATE KEY-----";
    public static final String passphrase2 = "password";
    public static final String certificate2 = "-----BEGIN CERTIFICATE-----\n" +
        "MIID0DCCArgCCQDqnPTUvA17+TANBgkqhkiG9w0BAQsFADCBqTELMAkGA1UEBhMC\n" +
        "VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR8wHQYDVQQK\n" +
        "ExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVLZXkgMjEiMCAGA1UE\n" +
        "AxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqGSIb3DQEJARYRZmhh\n" +
        "bmlrQHBpdm90YWwuaW8wHhcNMTcwNDEwMTkxNTAyWhcNMTgwNDEwMTkxNTAyWjCB\n" +
        "qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\n" +
        "c2NvMR8wHQYDVQQKExZDbG91ZCBGb3VuZHJ5IElkZW50aXR5MQ4wDAYDVQQLEwVL\n" +
        "ZXkgMjEiMCAGA1UEAxMZbG9naW4uaWRlbnRpdHkuY2YtYXBwLmNvbTEgMB4GCSqG\n" +
        "SIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
        "DwAwggEKAoIBAQDC3tu4hNFmFdf3xqlyAluIeGs+SuCfkwKwKmFFDz2hY9QdaM2P\n" +
        "0rPab0toqCr0Oc0uXbZTh7r8tRBOgEIvGQirBqhtkqMhSM0CY2iaps07sAPb4rtE\n" +
        "KJDaqKNZTBca77n59KYX8w56uY0pQOJCdElJJIA85sAc4j3zTNNZWwCkqlwVVpW+\n" +
        "T/b30v/SuTwj+Y29/rdx3Dg2HfGfgK36gKdNoODk62kbPyweWhw4C2L4t2u03Me4\n" +
        "Faryrax2EVAFEZ7Uw54fwIAQeApjAQtMEIkTIuHKR1GDFckdJovnr6ZvodC8Y7+j\n" +
        "Jkef6oewIKNx1HUv9Tiq3ibscGKa/Spu8ClDAgMBAAEwDQYJKoZIhvcNAQELBQAD\n" +
        "ggEBAKzeh/bRDEEP/WGsiYhCCfvESyt0QeKwUk+Hfl0/oP4m9pXNrnMRApyoi7FB\n" +
        "owpmXIeqDqGigPai6pJ3xCO94P+Bz7WTk0+jScYm/hGpcIOeKh8FBfW0Fddu9Otn\n" +
        "qVk0FdRSCTjUZKQlNOqVTjBeKOjHmTkgh96IR3EP2/hp8Ym4HLC+w265V7LnkqD2\n" +
        "SoMez7b2V4NmN7z9OxTALUbTzmFG77bBDExHvfbiFlkIptx8+IloJOCzUsPEg6Ur\n" +
        "kueuR7IB1S4q6Ja7Gb9b9NYQDFt4hjb5mC9aPxaX+KK2JlZg4cTFVCdkIyp2/fHI\n" +
        "iQpMzNWb7zZWlCfDL4dJZHYoNfg=\n" +
        "-----END CERTIFICATE-----";

    public static final String KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
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
    public static final String CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
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
    public static final String PASSWORD = "password";
}
