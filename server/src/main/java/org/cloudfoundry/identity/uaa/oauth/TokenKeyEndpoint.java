/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeysListResponse;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.lang.reflect.Field;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * OAuth2 token services that produces JWT encoded token values.
 *
 * @author Dave Syer
 * @author Luke Taylor
 * @author Joel D'sa
 */
@Controller
public class TokenKeyEndpoint implements InitializingBean {

    protected final Log logger = LogFactory.getLog(getClass());

    private SignerProvider signerProvider;

    /**
     * @param signerProvider the signerProvider to set
     */
    public void setSignerProvider(SignerProvider signerProvider) {
        this.signerProvider = signerProvider;
    }

    /**
     * Get the verification key for the token signatures. The principal has to
     * be provided only if the key is secret
     * (shared not public).
     *
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens
     */
    @RequestMapping(value = "/token_key", method = RequestMethod.GET)
    @ResponseBody
    public VerificationKeyResponse getKey(Principal principal) {
        KeyInfo key = signerProvider.getActiveKey();
        if (!includeSymmetricalKeys(principal) && !key.isPublic()) {
            throw new AccessDeniedException("You need to authenticate to see a shared key");
        }
        return getVerificationKeyResponse(key);
    }

    private VerificationKeyResponse getVerificationKeyResponse(KeyInfo key) {
        VerificationKeyResponse result = new VerificationKeyResponse();
        result.setAlgorithm(key.getSigner().algorithm());
        result.setKey(key.getVerifierKey());
        //new values per OpenID and JWK spec
        result.setType(key.getType());
        result.setUse("sig");
        result.setId(key.getKeyId());
        if (key.isPublic() && "RSA".equals(key.getType())) {
            SignatureVerifier verifier = key.getVerifier();
            if (verifier != null && verifier instanceof RsaVerifier) {
                RSAPublicKey rsaKey = extractRsaPublicKey((RsaVerifier) verifier);
                if (rsaKey != null) {
                    String n = new String(Base64.encode(rsaKey.getModulus().toByteArray()));
                    String e = new String(Base64.encode(rsaKey.getPublicExponent().toByteArray()));
                    result.setModulus(n);
                    result.setExponent(e);
                }
            }
        }
        return result;
    }

    /**
     * Get the verification key for the token signatures wrapped into keys array.
     * Wrapping done for compatibility with some clients expecting this even for single key, like mod_auth_openidc.
     * The principal has to be provided only if the key is secret
     * (shared not public).
     *
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens, wrapped in keys array
     */
    @RequestMapping(value = "/token_keys", method = RequestMethod.GET)
    @ResponseBody
    public VerificationKeysListResponse getKeys(Principal principal) {
        boolean includeSymmetric = includeSymmetricalKeys(principal);

        VerificationKeysListResponse result = new VerificationKeysListResponse();
        Map<String, KeyInfo> keys = signerProvider.getKeys();
        List<VerificationKeyResponse> keyResponses = keys.values().stream()
                .filter(k -> includeSymmetric || k.isPublic())
                .map(this::getVerificationKeyResponse)
                .collect(Collectors.toList());
        result.setKeys(keyResponses);
        return result;
    }

    protected boolean includeSymmetricalKeys(Principal principal) {
        if (principal!=null) {
            if (principal instanceof AnonymousAuthenticationToken) {
                return false;
            } else if (principal instanceof Authentication) {
                Authentication auth = (Authentication)principal;
                if (auth.getAuthorities()!=null) {
                    for (GrantedAuthority authority : auth.getAuthorities()) {
                        if ("uaa.resource".equals(authority.getAuthority())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }


    private RSAPublicKey extractRsaPublicKey(RsaVerifier verifier) {
        try {
            Field f = verifier.getClass().getDeclaredField("key");
            if (f != null) {
                f.setAccessible(true);
                if (f.get(verifier) instanceof RSAPublicKey) {
                    return (RSAPublicKey) f.get(verifier);
                }
            }
        } catch (NoSuchFieldException e) {

        } catch (IllegalAccessException e) {

        } catch (ClassCastException x) {

        }
        return null;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.state(this.signerProvider != null, "A SignerProvider must be provided");
    }
}
