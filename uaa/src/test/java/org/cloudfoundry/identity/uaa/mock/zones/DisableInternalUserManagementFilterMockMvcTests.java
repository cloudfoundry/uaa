package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@DefaultTestContext
class DisableInternalUserManagementFilterMockMvcTests {

    @Autowired
    WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    @Value("${disableInternalUserManagement:false}")
    private boolean disableInternalUserManagement;

    @BeforeEach
    void setUp() {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
    }

    @AfterEach
    void resetInternalUserManagement() {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, disableInternalUserManagement);
    }

    @Test
    void createAccountNotEnabled() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[@href='/create_account']").doesNotExist());
    }

    @Test
    void resetPasswordNotEnabled() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[@href='/forgot_password']").doesNotExist());
    }
}
