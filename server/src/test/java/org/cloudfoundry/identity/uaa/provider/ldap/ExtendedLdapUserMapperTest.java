package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExtendedLdapUserImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.NameAwareAttributes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserMapper.SUBSTITUTE_MAIL_ATTR_NAME;

class ExtendedLdapUserMapperTest {

    private Attributes attrs;
    private DirContextAdapter adapter;
    private ExtendedLdapUserMapper mapper;
    private Collection<GrantedAuthority> authorities;

    @BeforeEach
    void setUp() {
        attrs = new NameAwareAttributes();
        authorities = List.of();
        mapper = new ExtendedLdapUserMapper();
    }

    @Test
    void configureMailAttribute() {
        mapper = new ExtendedLdapUserMapper();
        mapper.setMailAttributeName("mail");
        mapper.setMailSubstitute("{0}@substitute.org");
        mapper.setMailSubstituteOverridesLdap(true);
        Map<String, String[]> records = new HashMap<>();
        String result = mapper.configureMailAttribute("marissa", records);
        assertThat(result).isEqualTo(SUBSTITUTE_MAIL_ATTR_NAME);
        assertThat(records.get(SUBSTITUTE_MAIL_ATTR_NAME)[0]).isEqualTo("marissa@substitute.org");

        mapper.setMailSubstituteOverridesLdap(false);
        result = mapper.configureMailAttribute("marissa", records);
        assertThat(result).isEqualTo(SUBSTITUTE_MAIL_ATTR_NAME);

        records.put("mail", new String[]{"marissa@test.org"});
        result = mapper.configureMailAttribute("marissa", records);
        assertThat(result).isEqualTo("mail");
    }

    @Test
    void givenNameAttributeNameMapping() throws Exception {
        attrs.put("givenName", "Marissa");
        adapter = new DirContextAdapter(attrs, new LdapName("cn=marissa,ou=Users,dc=test,dc=com"));
        mapper.setGivenNameAttributeName("givenName");

        ExtendedLdapUserImpl ldapUserDetails = getExtendedLdapUser();
        assertThat(ldapUserDetails.getGivenName()).isEqualTo("Marissa");
    }

    @Test
    void familyNameAttributeNameMapping() throws Exception {
        attrs.put("lastName", "Lastnamerton");
        adapter = new DirContextAdapter(attrs, new LdapName("cn=marissa,ou=Users,dc=test,dc=com"));
        mapper.setFamilyNameAttributeName("lastName");

        ExtendedLdapUserImpl ldapUserDetails = getExtendedLdapUser();
        assertThat(ldapUserDetails.getFamilyName()).isEqualTo("Lastnamerton");
    }

    @Test
    void phoneNumberAttributeNameMapping() throws Exception {
        attrs.put("phoneNumber", "8675309");
        adapter = new DirContextAdapter(attrs, new LdapName("cn=marissa,ou=Users,dc=test,dc=com"));
        mapper.setPhoneNumberAttributeName("phoneNumber");

        ExtendedLdapUserImpl ldapUserDetails = getExtendedLdapUser();
        assertThat(ldapUserDetails.getPhoneNumber()).isEqualTo("8675309");
    }

    private ExtendedLdapUserImpl getExtendedLdapUser() {
        UserDetails userDetails = mapper.mapUserFromContext(adapter, "marissa", authorities);
        assertThat(userDetails).isInstanceOf(ExtendedLdapUserImpl.class);
        return (ExtendedLdapUserImpl) userDetails;
    }

    @Test
    void noNPE() {
        ExtendedLdapUserImpl user = new ExtendedLdapUserImpl(Mockito.mock(ExtendedLdapUserDetails.class));
        user.setPassword("pass");
        assertThat(user.getPassword()).isEqualTo("pass");
    }
}
