package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.login.AddBcProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Collections;

public class GeneralIdentityZoneConfigurationValidatorTest {

    private IdentityZoneConfigurationValidator validator = new GeneralIdentityZoneConfigurationValidator();

    @BeforeClass
    public static void setUpBC() {
        AddBcProvider.noop();
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullSigningKey() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("key-id", null));
        config.setTokenPolicy(tokenPolicy);
        config.setSamlConfig(setSamlConfig());
        validator.validate(config, IdentityZoneConfigurationValidator.Mode.CREATE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptySigningKey() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("key-id", ""));
        config.setTokenPolicy(tokenPolicy);
        config.setSamlConfig(setSamlConfig());
        validator.validate(config, IdentityZoneConfigurationValidator.Mode.CREATE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullKeyId() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap(null, "signing-key"));
        config.setTokenPolicy(tokenPolicy);
        config.setSamlConfig(setSamlConfig());
        validator.validate(config, IdentityZoneConfigurationValidator.Mode.CREATE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyKeyId() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("", "signing-key"));
        config.setTokenPolicy(tokenPolicy);
        config.setSamlConfig(setSamlConfig());
        validator.validate(config, IdentityZoneConfigurationValidator.Mode.CREATE);
    }

    private SamlConfig setSamlConfig() {
        SamlConfig samlConfig = new SamlConfig();

        String samlPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
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
        String samlKeyPassphrase = "password";

        String samlCertificate = "-----BEGIN CERTIFICATE-----\n" +
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

        samlConfig.setCertificate(samlCertificate);
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);
        return samlConfig;
    }

}
