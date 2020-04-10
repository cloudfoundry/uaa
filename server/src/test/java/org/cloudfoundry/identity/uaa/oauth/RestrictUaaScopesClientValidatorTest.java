package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.RestrictUaaScopesClientValidator;
import org.cloudfoundry.identity.uaa.client.UaaScopes;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode.MODIFY;
import static org.junit.Assert.fail;


public class RestrictUaaScopesClientValidatorTest {

    List<String> goodScopes = Arrays.asList("openid","uaa.resource","uaa.none");
    List<String> badScopes = new UaaScopes().getUaaScopes();
    RestrictUaaScopesClientValidator validator = new RestrictUaaScopesClientValidator(new UaaScopes());

    @Test
    public void testValidate() {
        List<ClientDetailsValidator.Mode> restrictModes = Arrays.asList(CREATE, MODIFY);
        List<ClientDetailsValidator.Mode> nonRestrictModes = Collections.singletonList(DELETE);
        BaseClientDetails client = new BaseClientDetails("clientId","","","client_credentials,password","");

        for (String s : badScopes) {
            client.setScope(Collections.singletonList(s));
            validateClient(restrictModes, nonRestrictModes, client, s);
            client.setScope(Collections.EMPTY_LIST);
            client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(s)));
            validateClient(restrictModes, nonRestrictModes, client, s);
            client.setAuthorities(Collections.EMPTY_LIST);
        }

        for (String s : goodScopes) {
            List<ClientDetailsValidator.Mode> goodmodes = new LinkedList<>(restrictModes);
            goodmodes.addAll(nonRestrictModes);
            client.setScope(Collections.singletonList(s));
            validateClient(Collections.EMPTY_LIST, goodmodes, client, s);
            client.setScope(Collections.EMPTY_LIST);
            client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(s)));
            validateClient(Collections.EMPTY_LIST, goodmodes, client, s);
            client.setAuthorities(Collections.EMPTY_LIST);
        }

    }

    protected void validateClient(List<ClientDetailsValidator.Mode> restrictModes, List<ClientDetailsValidator.Mode> nonRestrictModes, BaseClientDetails client, String s) {
        for (ClientDetailsValidator.Mode m : restrictModes) {
            try {
                validator.validate(client, m);
                fail("Scope:"+s+" should not be valid during "+m+" mode.");
            } catch (InvalidClientDetailsException x) {
                //expected
            }
        }
        for (ClientDetailsValidator.Mode m : nonRestrictModes) {
            try {
                validator.validate(client, m);
            } catch (InvalidClientDetailsException x) {
                fail("Scope:"+s+" should be valid during "+m+" mode.");
            }
        }
    }


}