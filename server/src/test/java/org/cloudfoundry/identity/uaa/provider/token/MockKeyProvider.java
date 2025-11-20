package org.cloudfoundry.identity.uaa.provider.token;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;
import org.springframework.util.Base64Utils;

import java.util.HashMap;
import java.util.Map;

public class MockKeyProvider implements DevicePublicKeyProvider {


    Map<String, String> publicKeys = new HashMap<>();


    //TODO generate key
    public static final String ZONE1_PRIVATE_KEY = "TODO";

    static final String INCORRECT_TOKEN_SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
    + "MIIEowIBAAKCAQEAvBdlBa3I4sQNfwATpJ6I2aw5AfYqUqoc22fYpUg8hpUq2iXd\n"
    + "9MDmmoz+zbEv9hOAPi5U+/Gzye6ryqmnEdSt7onKQ/4Ar27kyaezxcrqNn5C6J4b\n"
    + "S8Z/pCpfSWse2xYq6dWgWXZbgKHzZh4rmcwOIc+buKef0up2Er6XEoYbDIUSl8+l\n"
    + "LtGlb+WeTnH8lmbvpP4y6I58L5zJsENCfTdCAZV9YVSai4wK23Y/cPMGnBAsASSJ\n"
    + "xiPKuGbBA9VXwHnYcutbwOd+6B2Tunintr9xZeyQ5kGyqu6AKsaDpCa6Letx/p8g\n"
    + "RqhXJdB2cBGjWSNR26pnq7GexSC0SnCtNz9ZiQIDAQABAoIBACUwgvryd4vOs9Ru\n"
    + "kXO1HN3dHZBzub6KgBYpnD5h4AXELKrhXdds5KueQSsuY4tGI88nngoKqj+8/x6d\n"
    + "GLl/0bweZm23JS+Kv5XXoMX07wZDRLt1t3PuFYLCFgEQOxOaeHWvlXra2hC+9L82\n"
    + "K+zG2ex5fhKuof0z+pCOOpShC2wX9N3t4uKIE5jDIRIDKZaOZzKWEe4k7trXH4Lx\n"
    + "rzjxOpHepubCp/z2ZGFP9DgfJPdf94ntUXdibwkU8EcGTXYAeZwLtzuw6fNJfSBJ\n"
    + "gCGv08GK6Py5/ax8OxUvsYtIZQW8bMkNR+iPLD4tMvcepuzTKcIhN/WCV7JH/y6X\n"
    + "neJ5UwECgYEA4P4M2TGSMJWk2BzR16HY+s53uAs73b7RTbTNI6FfZ8q8zE69aREo\n"
    + "k7Fyi8gpGtz1R7LLHgIoCI6mX4aHi3F+Y1dcc/010xzajKeEPI8GZLza4kQVOV+a\n"
    + "ewmky0R4F+4gI8e5G86HvSaQeJ4nJYnWhDJOO3MYiQOo9vu56bhyERkCgYEA1gNw\n"
    + "/YeFlpRXawQ4q2vNfzrchwezzKKKjwaeqCbJ/kRqHwHiuderZAvH7dHk4uKv6f93\n"
    + "Q8PoCJViKB5OEKijCWMMm6zumyfFaPNLBW1YIwltJIF6ThkSCwc8YGZwogyOwy5c\n"
    + "z9eRUHAlxbTNkUy10MHq2YwKvOt5r6oC0LrqafECgYEAkJxZj8QfzWBxeoJTkcAy\n"
    + "IUpRgpad3PHHv6VE8PDIzIJvhPXbIkvoA73a/OMjIGQCtxnBGcGTD6T4ZI+oUUUa\n"
    + "UimVf+uxC8cQ5bTJ9s6K8na8TRArgBvlw804AXo5ok/oknbNkITXlAjUdOJaEPOe\n"
    + "UIuw4t8gVvhmQpEbNpDZqAkCgYAai6i7OdEfIV1Kf+aLlL6Tlnh+Iz1xF4Q6Q2bw\n"
    + "kochi9jh6bj2tkKjETcGT6+lWNrbGn3voOAqGGVpdoDWXiSC6I9KzAN4qVE6OFtI\n"
    + "3Aw/pE6uZYUHJOLxDT+28V3tK8OVgC2w9hsnMBHvWQLaj/pJX5RC0bUPQ+H/IQZi\n"
    + "X5zt8QKBgBl2Zp8jSOkYA1LV8tzAWih51NR0ZoMVmXygZDfRdXwofJ8WqQCKwX66\n"
    + "n3xnWRSRszc7b10W+XLzJM4H5mcH0FpkiQKUZMYSE6mkyOFW5Yplzh/9cOvb2g4m\n"
    + "FVed3utJ8vGa/fHq+zv4EBlCLnBh0lKka5WzL1efTYa7mtoEUT/D\n"
    + "-----END RSA PRIVATE KEY-----\n";
    
    /*
     * keytool -genkey -keystore machine.jks -alias m -storepass <PASSWORD> -keypass <PASSWORD> -keyalg RSA -sigalg
     * SHA256withRSA -keysize 2048 -storetype JKS -validity 3650 -dname
     * "CN=dspmicro, OU=Predix, O=GE L=San Ramon, S=CA, C=US" -v
     * 
     * keytool -list -rfc -keystore machine.jks -alias m -storepass <PASSWORD>
     * 
     * keytool -list -rfc -keystore machine.jks -alias m -storepass <PASSWORD> > m.crt
     * 
     * keytool -v -importkeystore -srckeystore machine.jks -srcalias m -destkeystore mp12.p12 -deststoretype PKCS12
     * 
     * openssl pkcs12 -in mp12.p12 -nocerts -nodes
     * 
     * openssl x509 -in m.crt -pubkey -noout
     * 
     * openssl rsa -in priv.key -out old-format-priv.key
     * 
     */
    
    static final String DEVICE1_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEA1qEFBIQNuVVrF9UOy9AP7tfdCL19TmjKw16gXHfmSEJMcEzk\n"
            + "mM4/wZwStgtX8KFyhnzu3ZjQ9Mbd58Ddht+K1Zz32UN1V/vXT7TwocWWPUUNXbEn\n"
            + "3Tm6h7MCxbDyoGeXMQdFNq/w3bdHm/L0SOJCUjLnOMb0n1PTtq9hNNIT2RTLze/D\n"
            + "KabdKaq+oqTKGl1tqDZ8OKQs6PrgChcehuWBj+ZXaIaQmLeRWboyS1/H7u7iN3vP\n"
            + "pGMqt+/PK1jC87NPtTlq8EHMW8MyOmTUsuWEwWMr1bNcmI/snxpbwO9CeE3PwbT1\n"
            + "CzA+Ky0zGa++bBcaT3tPMoOef3XS1YCRXzMEKQIDAQABAoIBAQCJCutfRMpWinoF\n"
            + "D5+Q99sUkHSr/gIirLq7IJKYOF6ryNlx40cbYqZHA1bXMksGdK/hu6fxin/xq4FJ\n"
            + "V1abpeTKHJ4M9gvZEA8c79WuFbGmkY7FQjbIBPJbbyvX+vIRBdP+FDxXfOP5TevF\n"
            + "Yc4lM4NRZPtKv462pRnLzhPtXC4cLwXF1SwkTqU5xbU4T+TWf+CdJPaGW/dI3Lon\n"
            + "cW6Sor9X80OkATWvZYS/38Hp7eV1962wkfCBz1MPwWBjS/bXJOAWn42kAGRdcL20\n"
            + "K4P8hTVWNp4ZolO6dNGELtnDM5+0g+LDVNIMWPwqQlSWAvhqx39dCL8RV8jP2FGp\n"
            + "PPyiWZ/ZAoGBAO7bC+T1D/gDIgAIOM9WQhdF4wMfRFmc7JFOdC2BVJeQ+2RvL8s2\n"
            + "0KkSeUGN0pYSQI7SNyvrBv8aR2zIkwX5aY/Ck1AVZR+QzZE1QQ9d8kgle5UtQu/9\n"
            + "/xok+qVGvNcFLo9Nr0sheu04CGYxkkqmvWgxUdZw3LAjX7ZXRSeUWzULAoGBAOYI\n"
            + "z1+7Xn45a3i2/ynk58VaNFLqsYj/wZkWCKEZn7st2UvIVMpxs+KUk/I8LR1IdIDv\n"
            + "GfsGVWYeXu9IrBq0sfmg2HbE/0x6LM2pSBWYbtbKQJxlEZqwgzd2HuSzvlZncJjC\n"
            + "rGYDCpTGXyIiz4jzqWI3wfXJ8UKEQqODROJZ6MQbAoGAUtHY+faPJuvPKjuvlxTN\n"
            + "rcwpvrdkt73VuTx+xBiIAFXhFR4IcGn9R+KD8NsAHdEOWXdCchP4RRQTmACkGfo1\n"
            + "RAevlKEWgy9uV98jQ/TLQYDdrQgYoaZsgeA4mH5ClDvTvRSup1pgiUhYgTbHBuNx\n"
            + "4WLYgYZ4vwpE8bCo5eRnC6kCgYEAgWKnMZN0HM8zMdzMPMYxzwFjuNelMAea3v5T\n"
            + "sDl3bJLnTAbMGmpF4cXsSS2runLMhND37ger9RpUD4bytrq3+E6OMo+vgVae6La0\n"
            + "guEQRuPP36fBdR6fT4yy57Rp9LON03579Yz0YKYLUGoADWnv9fyirhr+BonZ6Zqm\n"
            + "HiKwF80CgYAjRguz6TpKViQKOUHUc5oKXRouysw4/0Tbxv15lLIWMVjbVX2xz13g\n"
            + "mHRwYixWdiLolgw/kwuzZ4wcZpIyn4TRK66UyTSG7LnY2Eh9xs6ZHLLHxDUNgHk6\n"
            + "Ob9JCpapUTY7oTo7oOIU9flKRMmg+UOR4ZwZZ1KLjqDhX/4rcmYOtQ==\n"
            + "-----END RSA PRIVATE KEY-----";

    static final String DEVICE1_PUBLIC_KEY =  "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qEFBIQNuVVrF9UOy9AP\n"
            + "7tfdCL19TmjKw16gXHfmSEJMcEzkmM4/wZwStgtX8KFyhnzu3ZjQ9Mbd58Ddht+K\n"
            + "1Zz32UN1V/vXT7TwocWWPUUNXbEn3Tm6h7MCxbDyoGeXMQdFNq/w3bdHm/L0SOJC\n"
            + "UjLnOMb0n1PTtq9hNNIT2RTLze/DKabdKaq+oqTKGl1tqDZ8OKQs6PrgChcehuWB\n"
            + "j+ZXaIaQmLeRWboyS1/H7u7iN3vPpGMqt+/PK1jC87NPtTlq8EHMW8MyOmTUsuWE\n"
            + "wWMr1bNcmI/snxpbwO9CeE3PwbT1CzA+Ky0zGa++bBcaT3tPMoOef3XS1YCRXzME\n"
            + "KQIDAQAB\n"
            + "-----END PUBLIC KEY-----";
    
    public static final String DEVICE_1 = "d1";
    public static final String DEVICE_2 = "d2";

    public String receivedZoneId;
    
    public MockKeyProvider() {
        //no test cases use tenant id for now
        this.publicKeys.put(DEVICE_1, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }
    
    @Override
    public String getPublicKey(String tenantId, String deviceId, String predixZoneId) throws PublicKeyNotFoundException {
        
        String key = publicKeys.get(deviceId);
        receivedZoneId = predixZoneId;

        if (null == key) {
            throw new PublicKeyNotFoundException();
        } else {
            // base64url encode this public key to replicate how real provider returns the key
            return Base64Utils.encodeToString(key.getBytes());
        }
    }

    @Override
    public String getPublicKeyWithToken(String tenantId, String deviceId, String predixZoneId, String token) throws PublicKeyNotFoundException {
        String key = publicKeys.get(deviceId);
        receivedZoneId = predixZoneId;

        if (null == key) {
            throw new PublicKeyNotFoundException();
        } else {
            // base64url encode this public key to replicate how real provider returns the key
            return Base64Utils.encodeToString(key.getBytes());
        }
    }
}
