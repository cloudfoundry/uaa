package org.cloudfoundry.identity.uaa.cypto;

import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class ActiveEncryptionKeyServiceTest {
    private ActiveEncryptionKeyService activeEncryptionKeyService;
    private List<ActiveEncryptionKeyService.EncryptionKey> encryptionKeys;

    @Before
    public void setup() {
        encryptionKeys = new ArrayList<>();
        encryptionKeys.add(new ActiveEncryptionKeyService.EncryptionKey() {{
            put("label", "active-key");
            put("passphrase", "some-passphrase");
        }});

        encryptionKeys.add(new ActiveEncryptionKeyService.EncryptionKey() {{
            put("label", "active-key2");
            put("passphrase", "some-passphrase2");
        }});

        activeEncryptionKeyService = new ActiveEncryptionKeyService("active-key", encryptionKeys);
    }

    @Test
    public void shouldFetchValidEncryptionActiveKeyPassphrase() {
        String passphrase = activeEncryptionKeyService.getPassphrase();

        assertThat(passphrase, is("some-passphrase"));
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldThrowErrorIfActiveEncryptionKeyHasNotBeenProvided() {
        String activeKeyLabel = "active-key" + System.currentTimeMillis();
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage(String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s] is undefined", activeKeyLabel));

        activeEncryptionKeyService = new ActiveEncryptionKeyService(activeKeyLabel, new ArrayList<>());
    }

    @Test
    public void shouldThrowErrorIfNoActiveKeyLabelIsProvided() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("UAA cannot be started without encryption key value uaa.encryption.active_key_label");

        activeEncryptionKeyService = new ActiveEncryptionKeyService("", new ArrayList<>());
    }

    @Test
    public void eachEncryptionKeyShouldHaveANonEmptyPassphrase() {
        String key2 = "key2" + System.currentTimeMillis();
        String key3 = "key3" + System.currentTimeMillis();

        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage(
          String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s, label=%s] is undefined", key2, key3)
        );

        ActiveEncryptionKeyService.EncryptionKey activeEncryptionKey = new ActiveEncryptionKeyService.EncryptionKey();
        activeEncryptionKey.put("label", "key1");
        activeEncryptionKey.put("passphrase", "123456789");

        ActiveEncryptionKeyService.EncryptionKey encryptionKey2 = new ActiveEncryptionKeyService.EncryptionKey();
        encryptionKey2.put("label", key2);
        encryptionKey2.put("passphrase", "");


        ActiveEncryptionKeyService.EncryptionKey encryptionKey3 = new ActiveEncryptionKeyService.EncryptionKey();
        encryptionKey3.put("label", key3);
        encryptionKey3.put("passphrase", "");

        activeEncryptionKeyService =
          new ActiveEncryptionKeyService("key1", Lists.newArrayList(activeEncryptionKey, encryptionKey2, encryptionKey3));
    }
}
