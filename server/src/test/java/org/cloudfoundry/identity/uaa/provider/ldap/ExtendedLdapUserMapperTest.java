package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExtendedLdapUserImpl;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.NameAwareAttributes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserMapper.SUBSTITUTE_MAIL_ATTR_NAME;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class ExtendedLdapUserMapperTest  {

    private Attributes attrs;
    private DirContextAdapter adapter;
    private ExtendedLdapUserMapper mapper;
    private Collection<GrantedAuthority> authorities;
    private String UAA_MANAGER;

    @Before
    public void setUp() {
        attrs = new NameAwareAttributes();
        authorities = Collections.<GrantedAuthority>emptyList();
        mapper = new ExtendedLdapUserMapper();
    }

    @Test
    public void testConfigureMailAttribute() {
        ExtendedLdapUserMapper mapper = new ExtendedLdapUserMapper();
        mapper.setMailAttributeName("mail");
        mapper.setMailSubstitute("{0}@substitute.org");
        mapper.setMailSubstituteOverridesLdap(true);
        Map<String, String[]> records = new HashMap<>();
        String result = mapper.configureMailAttribute("marissa", records);
        assertEquals(SUBSTITUTE_MAIL_ATTR_NAME, result);
        assertEquals("marissa@substitute.org", records.get(SUBSTITUTE_MAIL_ATTR_NAME)[0]);

        mapper.setMailSubstituteOverridesLdap(false);
        result = mapper.configureMailAttribute("marissa", records);
        assertEquals(SUBSTITUTE_MAIL_ATTR_NAME, result);

        records.put("mail", new String[] {"marissa@test.org"});
        result = mapper.configureMailAttribute("marissa", records);
        assertEquals("mail", result);
    }

    @Test
    public void testGivenNameAttributeNameMapping() throws Exception {
        attrs.put("givenName", "Marissa");
        adapter = new DirContextAdapter(attrs, new LdapName("cn=marissa,ou=Users,dc=test,dc=com"));
        mapper.setGivenNameAttributeName("givenName");

        ExtendedLdapUserImpl ldapUserDetails = getExtendedLdapUser();
        Assert.assertThat(ldapUserDetails.getGivenName(), is("Marissa"));
    }

    @Test
    public void testFamilyNameAttributeNameMapping() throws Exception {
        attrs.put("lastName", "Lastnamerton");
        adapter = new DirContextAdapter(attrs, new LdapName("cn=marissa,ou=Users,dc=test,dc=com"));
        mapper.setFamilyNameAttributeName("lastName");

        ExtendedLdapUserImpl ldapUserDetails = getExtendedLdapUser();
        Assert.assertThat(ldapUserDetails.getFamilyName(), is("Lastnamerton"));
    }

    @Test
    public void testPhoneNumberAttributeNameMapping() throws Exception {
        attrs.put("phoneNumber", "8675309");
        adapter = new DirContextAdapter(attrs, new LdapName("cn=marissa,ou=Users,dc=test,dc=com"));
        mapper.setPhoneNumberAttributeName("phoneNumber");

        ExtendedLdapUserImpl ldapUserDetails = getExtendedLdapUser();
        Assert.assertThat(ldapUserDetails.getPhoneNumber(), is("8675309"));
    }

    private ExtendedLdapUserImpl getExtendedLdapUser() {
        UserDetails userDetails = mapper.mapUserFromContext(adapter, "marissa", authorities);
        assertThat(userDetails instanceof ExtendedLdapUserImpl, is(true));
        return (ExtendedLdapUserImpl)userDetails;
    }
}