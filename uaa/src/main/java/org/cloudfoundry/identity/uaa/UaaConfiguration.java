package org.cloudfoundry.identity.uaa;

import javax.validation.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.config.CustomPropertyConstructor;
import org.hibernate.validator.constraints.URL;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;

/**
 * Java representation of the UAA YAML configuration for validation purposes.
 *
 * @author Luke Taylor
 */
public class UaaConfiguration {
	public String name;
	@Pattern(regexp="(default|postgresql|hsqldb|mysql)")
	public String platform;
	public String spring_profiles;
	@URL(message = "issuer.uri must be a valid URL")
	public String issuerUri;
	public boolean dump_requests;
	public boolean require_https;
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
		}
	}

	public static class OAuth {
		@Valid
		public Client client;
		@Valid
		public Authorize authorize;
		@Valid
		public Map<String,OAuthClient> clients;

		public static class Client {
			public String override;
			public List<String> autoapprove;
		}

		public static class Authorize {
			@NotNull
			public boolean ssl;
		}
	}

	public static class OAuthClient {
		@NotNull(message = "Each oauth client requires an 'id'")
		public String id;
		public boolean override;
		public String scope;
		public String secret;
		public String authorities;
		@NotNull
		public String grantTypes;
		public String accessTokenValidity;
		public String refreshTokenValidity;
		@URL(message = "'redirect-uri' must be a valid URL")
		public String redirectUri;
	}

	public static class Scim {
		public boolean userids_enabled;
		public boolean userOverride;
		public List<String> users;
	}

	public static class UaaConfigConstructor extends CustomPropertyConstructor {

		public UaaConfigConstructor() {
			super(UaaConfiguration.class);
			TypeDescription oauthDesc = new TypeDescription(OAuth.class);
			oauthDesc.putMapPropertyType("clients", String.class, OAuthClient.class);
			addTypeDescription(oauthDesc);
			addPropertyAlias("issuer.uri", UaaConfiguration.class, "issuerUri");
			addPropertyAlias("signing-key", Jwt.Token.class, "signingKey");
			addPropertyAlias("verification-key", Jwt.Token.class, "verificationKey");
			addPropertyAlias("authorized-grant-types", OAuthClient.class, "grantTypes");
			addPropertyAlias("redirect-uri", OAuthClient.class, "redirectUri");
			addPropertyAlias("access-token-validity", OAuthClient.class, "accessTokenValidity");
			addPropertyAlias("refresh-token-validity", OAuthClient.class, "refreshTokenValidity");
			addPropertyAlias("user.override", Scim.class, "userOverride");
		}
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			throw new IllegalArgumentException("YAML file required");
		}
		Yaml yaml = new Yaml(new UaaConfigConstructor());
		BufferedReader br = new BufferedReader(new FileReader(args[0]));
		UaaConfiguration config = (UaaConfiguration) yaml.load(br);
		ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
		Validator validator = factory.getValidator();
		Set<ConstraintViolation<UaaConfiguration>> errors = validator.validate(config);
		System.out.println(errors);
	}
}
