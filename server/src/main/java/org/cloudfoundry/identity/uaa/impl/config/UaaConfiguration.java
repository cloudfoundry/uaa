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
package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration.Jwt.Token.Claims;
import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration.Jwt.Token.Policy;
import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration.Jwt.Token.Policy.KeySpec;
import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration.OAuth.Client;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.hibernate.validator.constraints.URL;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.AbstractConstruct;
import org.yaml.snakeyaml.constructor.Construct;
import org.yaml.snakeyaml.nodes.Node;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Valid;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Java representation of the UAA YAML configuration for validation purposes.
 *
 * @author Luke Taylor
 */
public class UaaConfiguration {
    public boolean disableInternalUserManagement;
    public boolean disableInternalAuth;

    public String name;
    @Pattern(regexp = "(default|postgresql|hsqldb|mysql|oracle)")
    public String platform;
    public String spring_profiles;

    @Valid
    public Zones zones;

    @URL(message = "issuer.uri must be a valid URL")
    public String issuerUri;
    public Map<String, Object> issuer;
    public boolean dump_requests;
    public boolean require_https;
    public boolean loginAddnew;
    public boolean allowUnverifiedUsers;
    @Valid
    public PasswordPolicy passwordPolicy;
    @Valid
    public Database database;
    @Valid
    public Logging logging;
    @Valid
    public Jwt jwt;
    @Valid
    public OAuth oauth;
    @Valid
    public Scim scim;
    @Valid
    public CloudController cloud_controller;
    @Valid
    public Map<String, Object> ldap;

    @Valid
    public Map<String, Object> login;
    @Valid
    public Map<String, Object> logout;
    @Valid
    public Map<String, Object> links;
    @Valid
    public Map<String, Object> smtp;
    @Valid
    public Map<String, Object> tiles;
    @Valid
    public Map<String, Object> servlet;
    @Valid
    public Map<String, Object> password;
    @Valid
    public Map<String, Object> authentication;
    @Valid
    public Map<String, Object> notifications;
    @Valid
    public Map<String, Object> uaa;
    @Valid
    public String assetBaseUrl;
    @Valid
    public String LOGIN_SECRET;
    @Valid
    public OAuth multitenant;
    @Valid
    public Map<String, Object> cors;

    public Encryption encryption;

    public Integer userMaxCount;
    public Integer groupMaxCount;
    public Integer clientMaxCount;
    public RateLimit ratelimit;

    public static class Zones {
        @Valid
        public InternalZone internal;

        public static class InternalZone {
            public Set<String> hostnames;
        }
    }

    public static class CloudController {
        @Valid
        public Database database;
    }

    public static class Database {
        public String driverClassName;
        @NotNull(message = "Database url is required")
        public String url;
        @NotNull(message = "Database username is required")
        public String username;
        @NotNull(message = "Database password is required")
        public String password;
        public boolean caseinsensitive;

        public int maxactive;
        public int maxidle;
        public boolean removeabandoned;
        public boolean logabandoned;
        public int abandonedtimeout;
        public long evictionintervalms;

    }

    public static class Logging {
        @NotNull(message = "'logging:' needs a 'config' file location")
        public String config;
    }

    public static class Jwt {
        @NotNull(message = "'jwt:' requires a 'token:' block")
        public Token token;

        public static class Token {
            @NotNull(message = "'token:' requires 'signing-key'")
            public String signingKey;
            public String verificationKey;
            public String signingCert;
            public String signingAlg;
            public Claims claims;
            public Policy policy;
            public Boolean revocable;
            public Refresh refresh;

            public static class Claims {
                public Set<String> exclusions;
            }

            public static class Policy {
                public String activeKeyId;
                public Map<String, KeySpec> keys;
                public Policy global;
                public int accessTokenValiditySeconds;
                public int refreshTokenValiditySeconds;

                public static class KeySpec {
                    public String signingKey;
                    public String signingKeyPassword;
                    public String signingAlg;
                }
            }

            public static class Refresh {
                public String format;
                public Boolean rotate;
                public Boolean unique;
            }
        }
    }

    public static class OAuth {
        @Valid
        public Client client;
        @Valid
        public Authorize authorize;
        @Valid
        public Map<String, OAuthClient> clients;
        @Valid
        public User user;

        public OpenID openid;

        public static class Client {
            public String override;
            public List<String> autoapprove;
            public List<String> allowpublic;
        }

        public static class Authorize {
            @NotNull
            public boolean ssl;
        }

        public static class User {
            @Valid
            public Set<String> authorities;
        }

        public static class OpenID {
            public boolean fallbackToAuthcode;
        }
    }

    public static class OAuthClient {
        @NotNull(message = "Each oauth client requires an 'id'")
        public String id;
        public boolean override;
        public List<String> autoapprove;
        public List<String> allowpublic;
        public String scope;
        public String secret;
        public String authorities;
        @NotNull
        public String grantTypes;
        public String accessTokenValidity;
        public String refreshTokenValidity;
        @URL(message = "'redirect-uri' must be a valid URL")
        public String redirectUri;
        public String jwks;
        public String signup_redirect_url;
        public String change_email_redirect_url;
        public String name;
        public List<String> allowedproviders;
        public String useBcryptPrefix;
        public String jwks_uri;
        public String jwt_creds;
    }

    public static class Scim {
        public boolean userids_enabled;
        public boolean userOverride;
        public List<String> users;
        public List<String> external_groups;
        public Object groups;
    }

    public static class PasswordPolicy {
        public int requiredScore;
    }

    public static class Encryption {
        public String active_key_label;
        public String passkey;
        public List<EncryptionKey> encryption_keys;

        public static class EncryptionKey {
            public String label;
        }
    }

    public static class RateLimit {
        public String loggingOption;
        public String credentialID;
        public List<LimiterMapping> limiterMappings;
    }


    public static class UaaConfigConstructor extends CustomPropertyConstructor {

        public UaaConfigConstructor() {
            super(UaaConfiguration.class);
            var uaaDesc = typeDefinitions.get(UaaConfiguration.class);
            uaaDesc.putMapPropertyType("issuer", String.class, Object.class);

            TypeDescription oauthDesc = createTypeDescription(OAuth.class);
            oauthDesc.putMapPropertyType("clients", String.class, OAuthClient.class);
            addTypeDescription(oauthDesc);

            TypeDescription clientDesc = createTypeDescription(Client.class);
            clientDesc.putListPropertyType(ClientConstants.AUTO_APPROVE, String.class);
            addTypeDescription(clientDesc);

            TypeDescription oauthClientDesc = createTypeDescription(OAuthClient.class);
            oauthClientDesc.putListPropertyType(ClientConstants.AUTO_APPROVE, String.class);
            addTypeDescription(oauthClientDesc);

            TypeDescription claimsDesc = createTypeDescription(Claims.class);
            claimsDesc.putListPropertyType("exclusions", String.class);
            addTypeDescription(clientDesc);

            TypeDescription policyDesc = createTypeDescription(Policy.class);
            policyDesc.putMapPropertyType("keys", String.class, KeySpec.class);
            addTypeDescription(policyDesc);

            addPropertyAlias("issuer.uri", UaaConfiguration.class, "issuerUri");
            // login.addnew is ignored - it is not needed anymore.
            addPropertyAlias("login.addnew", UaaConfiguration.class, "loginAddnew");
            addPropertyAlias("password-policy", UaaConfiguration.class, "passwordPolicy");
            addPropertyAlias("required-score", PasswordPolicy.class, "requiredScore");
            addPropertyAlias("signing-key", Jwt.Token.class, "signingKey");
            addPropertyAlias("signing-alg", Jwt.Token.class, "signingAlg");
            addPropertyAlias("signing-cert", Jwt.Token.class, "signingCert");
            addPropertyAlias("verification-key", Jwt.Token.class, "verificationKey");
            addPropertyAlias("exclude", Jwt.Token.Claims.class, "exclusions");
            addPropertyAlias("authorized-grant-types", OAuthClient.class, "grantTypes");
            addPropertyAlias("redirect-uri", OAuthClient.class, "redirectUri");
            addPropertyAlias("access-token-validity", OAuthClient.class, "accessTokenValidity");
            addPropertyAlias("refresh-token-validity", OAuthClient.class, "refreshTokenValidity");
            addPropertyAlias("user.override", Scim.class, "userOverride");
            addPropertyAlias("use-bcrypt-prefix", OAuthClient.class, "useBcryptPrefix");
        }

        @Override
        protected Construct getConstructor(Node node) {
            if (List.class.isAssignableFrom(node.getType())) {
                return new AbstractConstruct() {
                    @Override
                    public Object construct(Node node) {
                        return new ArrayList<Object>();
                    }
                };
            }
            return super.getConstructor(node);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("YAML file required");
        }
        Yaml yaml = new Yaml(new UaaConfigConstructor());
        try (InputStreamReader inputStreamReader = new FileReader(args[0])) {
            BufferedReader br = new BufferedReader(inputStreamReader);
            UaaConfiguration config = (UaaConfiguration) yaml.load(br);
            ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
            Validator validator = factory.getValidator();
            Set<ConstraintViolation<UaaConfiguration>> errors = validator.validate(config);
            System.out.println(errors);
        }
    }
}
