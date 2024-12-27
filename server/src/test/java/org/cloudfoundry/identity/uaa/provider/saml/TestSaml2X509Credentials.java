/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.util.encoders.Base64;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * This was copied from Spring Security Test Classes
 * Migrate to use the Spring Security class when it is made public
 * <p>
 * Changed:
 * privateKey/decodePrivateKey no longer uses bouncycastle and cryptacular with does not work with FIPS mode.
 */
public final class TestSaml2X509Credentials {

    private TestSaml2X509Credentials() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static Saml2X509Credential assertingPartySigningCredential() {
        return new Saml2X509Credential(idpPrivateKey(), idpCertificate(), Saml2X509CredentialType.SIGNING);
    }

    public static Saml2X509Credential assertingPartyEncryptingCredential() {
        return new Saml2X509Credential(spCertificate(), Saml2X509CredentialType.ENCRYPTION);
    }

    public static Saml2X509Credential assertingPartyPrivateCredential() {
        return new Saml2X509Credential(idpPrivateKey(), idpCertificate(), Saml2X509CredentialType.SIGNING,
                Saml2X509CredentialType.DECRYPTION);
    }

    public static Saml2X509Credential relyingPartyVerifyingCredential() {
        return new Saml2X509Credential(idpCertificate(), Saml2X509CredentialType.VERIFICATION);
    }

    public static Saml2X509Credential relyingPartyEncryptingCredential() {
        return new Saml2X509Credential(idpCertificate(), Saml2X509CredentialType.ENCRYPTION);
    }

    public static Saml2X509Credential relyingPartySigningCredential() {
        return new Saml2X509Credential(spPrivateKey(), spCertificate(), Saml2X509CredentialType.SIGNING);
    }

    public static Saml2X509Credential relyingPartyDecryptingCredential() {
        return new Saml2X509Credential(spPrivateKey(), spCertificate(), Saml2X509CredentialType.DECRYPTION);
    }

    public static Saml2X509Credential altPublicCredential() {
        return new Saml2X509Credential(altCertificate(), Saml2X509CredentialType.VERIFICATION,
                Saml2X509CredentialType.ENCRYPTION);
    }

    public static Saml2X509Credential altPrivateCredential() {
        return new Saml2X509Credential(altPrivateKey(), altCertificate(), Saml2X509CredentialType.SIGNING,
                Saml2X509CredentialType.DECRYPTION);
    }

    private static X509Certificate certificate(String cert) {
        ByteArrayInputStream certBytes = new ByteArrayInputStream(cert.getBytes());
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certBytes);
        } catch (CertificateException ex) {
            throw new Saml2Exception(ex);
        }
    }

    private static PrivateKey privateKey(String key) {
        key = key.replace("-----BEGIN PRIVATE KEY-----", "");
        key = key.replace("-----END PRIVATE KEY-----", "");
        key = key.replaceAll("\\s+", "");
        return decodePrivateKey(key.getBytes(StandardCharsets.UTF_8));
    }

    private static PrivateKey decodePrivateKey(byte[] keyBytes) {
        try {
            byte[] pkcs8EncodedBytes = Base64.decode(keyBytes);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Saml2Exception(e);
        }
    }

    private static X509Certificate idpCertificate() {
        return certificate(
                """
                -----BEGIN CERTIFICATE-----
                MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD
                VQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYD
                VQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwX
                c2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0Bw
                aXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJ
                BgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAa
                BgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQD
                DBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlr
                QHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62
                E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz
                2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWW
                RDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQ
                nX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5
                cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gph
                iJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5
                ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTAD
                AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduO
                nRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+v
                ZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLu
                xbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6z
                V9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3
                lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk
                -----END CERTIFICATE-----""");
    }

    private static PrivateKey idpPrivateKey() {
        return privateKey("""
                -----BEGIN PRIVATE KEY-----
                MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4cn62E1xLqpN3
                4PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZX
                W+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHE
                fDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7h
                Z6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/T
                Xy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7
                I+J5lS8VAgMBAAECggEBAKyxBlIS7mcp3chvq0RF7B3PHFJMMzkwE+t3pLJcs4cZ
                nezh/KbREfP70QjXzk/llnZCvxeIs5vRu24vbdBm79qLHqBuHp8XfHHtuo2AfoAQ
                l4h047Xc/+TKMivnPQ0jX9qqndKDLqZDf5wnbslDmlskvF0a/MjsLU0TxtOfo+dB
                t55FW11cGqxZwhS5Gnr+cbw3OkHz23b9gEOt9qfwPVepeysbmm9FjU+k4yVa7rAN
                xcbzVb6Y7GCITe2tgvvEHmjB9BLmWrH3mZ3Af17YU/iN6TrpPd6Sj3QoS+2wGtAe
                HbUs3CKJu7bIHcj4poal6Kh8519S+erJTtqQ8M0ZiEECgYEA43hLYAPaUueFkdfh
                9K/7ClH6436CUH3VdizwUXi26fdhhV/I/ot6zLfU2mgEHU22LBECWQGtAFm8kv0P
                zPn+qjaR3e62l5PIlSYbnkIidzoDZ2ztu4jF5LgStlTJQPteFEGgZVl5o9DaSZOq
                Yd7G3XqXuQ1VGMW58G5FYJPtA1cCgYEAz5TPUtK+R2KXHMjUwlGY9AefQYRYmyX2
                Tn/OFgKvY8lpAkMrhPKONq7SMYc8E9v9G7A0dIOXvW7QOYSapNhKU+np3lUafR5F
                4ZN0bxZ9qjHbn3AMYeraKjeutHvlLtbHdIc1j3sxe/EzltRsYmiqLdEBW0p6hwWg
                tyGhYWVyaXMCgYAfDOKtHpmEy5nOCLwNXKBWDk7DExfSyPqEgSnk1SeS1HP5ctPK
                +1st6sIhdiVpopwFc+TwJWxqKdW18tlfT5jVv1E2DEnccw3kXilS9xAhWkfwrEvf
                V5I74GydewFl32o+NZ8hdo9GL1I8zO1rIq/et8dSOWGuWf9BtKu/vTGTTQKBgFxU
                VjsCnbvmsEwPUAL2hE/WrBFaKocnxXx5AFNt8lEyHtDwy4Sg1nygGcIJ4sD6koQk
                RdClT3LkvR04TAiSY80bN/i6ZcPNGUwSaDGZEWAIOSWbkwZijZNFnSGOEgxZX/IG
                yd39766vREEMTwEeiMNEOZQ/dmxkJm4OOVe25cLdAoGACOtPnq1Fxay80UYBf4rQ
                +bJ9yX1ulB8WIree1hD7OHSB2lRHxrVYWrglrTvkh63Lgx+EcsTV788OsvAVfPPz
                BZrn8SdDlQqalMxUBYEFwnsYD3cQ8yOUnijFVC4xNcdDv8OIqVgSk4KKxU5AshaA
                xk6Mox+u8Cc2eAK12H13i+8=
                -----END PRIVATE KEY-----""");
    }

    private static X509Certificate spCertificate() {
        return certificate("""
                -----BEGIN CERTIFICATE-----
                MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
                VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG
                A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD
                DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1
                MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES
                MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN
                TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s
                MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos
                vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM
                +U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG
                y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi
                XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+
                qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD
                RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B
                -----END CERTIFICATE-----""");
    }

    private static PrivateKey spPrivateKey() {
        return privateKey("""
                -----BEGIN PRIVATE KEY-----
                MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANG7v8QjQGU3MwQE
                VUBxvH6Uuiy/MhZT7TV0ZNjyAF2ExA1gpn3aUxx6jYK5UnrpxRRE/KbeLucYbOhK
                cDECt77Rggz5TStrOta0BQTvfluRyoQtmQ5Nkt6Vqg7O2ZapFt7k64Sal7AftzH6
                Q2BxWN1y04bLdDrH4jipqRj/2qEFAgMBAAECgYEAj4ExY1jjdN3iEDuOwXuRB+Nn
                x7pC4TgntE2huzdKvLJdGvIouTArce8A6JM5NlTBvm69mMepvAHgcsiMH1zGr5J5
                wJz23mGOyhM1veON41/DJTVG+cxq4soUZhdYy3bpOuXGMAaJ8QLMbQQoivllNihd
                vwH0rNSK8LTYWWPZYIECQQDxct+TFX1VsQ1eo41K0T4fu2rWUaxlvjUGhK6HxTmY
                8OMJptunGRJL1CUjIb45Uz7SP8TPz5FwhXWsLfS182kRAkEA3l+Qd9C9gdpUh1uX
                oPSNIxn5hFUrSTW1EwP9QH9vhwb5Vr8Jrd5ei678WYDLjUcx648RjkjhU9jSMzIx
                EGvYtQJBAMm/i9NR7IVyyNIgZUpz5q4LI21rl1r4gUQuD8vA36zM81i4ROeuCly0
                KkfdxR4PUfnKcQCX11YnHjk9uTFj75ECQEFY/gBnxDjzqyF35hAzrYIiMPQVfznt
                YX/sDTE2AdVBVGaMj1Cb51bPHnNC6Q5kXKQnj/YrLqRQND09Q7ParX0CQQC5NxZr
                9jKqhHj8yQD6PlXTsY4Occ7DH6/IoDenfdEVD5qlet0zmd50HatN2Jiqm5ubN7CM
                INrtuLp4YHbgk1mi
                -----END PRIVATE KEY-----""");
    }

    private static X509Certificate altCertificate() {
        return certificate("""
                -----BEGIN CERTIFICATE-----
                MIICkDCCAfkCFEstVfmWSFQp/j88GaMUwqVK72adMA0GCSqGSIb3DQEBCwUAMIGG
                MQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjESMBAGA1UEBwwJVmFu
                Y291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FNTDEMMAoGA1UECwwD
                YWx0MSEwHwYDVQQDDBhhbHQuc3ByaW5nLnNlY3VyaXR5LnNhbWwwHhcNMjIwMjEw
                MTY1ODA4WhcNMzIwMjEwMTY1ODA4WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgM
                Cldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5n
                IFNlY3VyaXR5IFNBTUwxDDAKBgNVBAsMA2FsdDEhMB8GA1UEAwwYYWx0LnNwcmlu
                Zy5zZWN1cml0eS5zYW1sMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9ZGWj
                TPDsymQCJL044py4xLsBI/S9RvzNeR9oD/tHyoxCE+YZzjf0PyBtwqKzkKWqCPf4
                XGUYHfEpkM5kJYwCW8TsOx5fnwLIQweiPqjYrBr/O0IjHMqYG9HlR/ros7iBt4ab
                EGUu/B9yYg1YRYPxKQ6TNP3AD+9tBT8TsFFyjwIDAQABMA0GCSqGSIb3DQEBCwUA
                A4GBAKJf2VHLjkCHRxlbWn63jGiquq3ENYgd1JS0DZ3ggFmuc6zQiqxzRGtArIDZ
                0jH5nrG0jcvO0fqDqBQh0iT8thfUnkViAQvACZ9a+0x0NzUicJ+Ra51c8Z2enqbg
                pXy+ga67HcAXrDekm1MCGCgiEb/Cgl41lsideqhC8Efl7PRN
                -----END CERTIFICATE-----""");
    }

    private static PrivateKey altPrivateKey() {
        return privateKey("""
                -----BEGIN PRIVATE KEY-----
                MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAL1kZaNM8OzKZAIk
                vTjinLjEuwEj9L1G/M15H2gP+0fKjEIT5hnON/Q/IG3CorOQpaoI9/hcZRgd8SmQ
                zmQljAJbxOw7Hl+fAshDB6I+qNisGv87QiMcypgb0eVH+uizuIG3hpsQZS78H3Ji
                DVhFg/EpDpM0/cAP720FPxOwUXKPAgMBAAECgYEApYKslAZ0cer5dSoYNzNLFOnQ
                J1H92r/Dw+k6+h0lUvr+keyD5T9jhM76DxHOUDBzpmIKGoDcVDQugk2rILfzXsQA
                JtwvDRJk32Z02Vt0jb7t/WUOOQhjKCjQuv9/tOx90GCl0VxYG69UOjaMRWrlg/i9
                6/zcTRIahIn5XxF0psECQQD7ivJCpDbOLJGsc8gNJR4cvjZ1q0mHIOrbKqJC0y1n
                5DrzGEflPeyCUwnOKNp9HJQP8gmZzXfj0JM9KsjpiUChAkEAwL+FmhDoTiqStIrH
                h9Kdnsev//imMmRHxjwDhntYvqavUsISRmY3imd8inoYq5dzWQMzBtoTyMRmqeLT
                DHV1LwJAW4xaV37Eo4z9B7Kr4Hzd1MA1ueW5QQDt+Q4vN/r7z4/1FHyFzh0Xcucd
                7nZX7qj0CkmgzOVG+Rb0P5LOxJA7gQJBAK1KQ2qNct375qPM9bEGSVGchH6k5X7+
                q4ztHdpFgTb/EzdbZiTG935GpjC1rwJuinTnrHOnkwv4j7iDRm24GF8CQQDqPvrQ
                GcItR6UUy0q/B8UxLzlE6t+HiznfiJKfyGgCHU56Y4/ZhzSQz2MZHz9SK4DsUL9s
                bOYrWq8VY2fyjV1t
                -----END PRIVATE KEY-----""");
    }
}
