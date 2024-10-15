package org.wso2.carbon.identity.fraud.detection.util;

import org.json.JSONObject;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class UtilTest {

    @Mock
    private JsAuthenticationContext mockContext;

    @Mock
    private IdentityGovernanceService mockIdentityGovernanceService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        SiftDataHolder.getInstance().setIdentityGovernanceService(mockIdentityGovernanceService);
    }

    @Test
    public void testBuildPayload() throws FrameworkException, IdentityGovernanceException, UserIdNotFoundException {

        // Mock the wrapped context
        AuthenticationContext wrappedContext = mock(AuthenticationContext.class);
        when(mockContext.getWrapped()).thenReturn(wrappedContext);

        when(mockContext.getWrapped().getTenantDomain()).thenReturn("carbon.super");
        when(mockContext.getWrapped().getSessionIdentifier()).thenReturn("session123");

        // Mock the JsGraalAuthenticatedUser
        JsGraalAuthenticatedUser mockUser = mock(JsGraalAuthenticatedUser.class);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(mockUser.getWrapped()).thenReturn(authenticatedUser);
        when(mockUser.getWrapped().getUserId()).thenReturn("user123");

        // Mock the context.getMember(Constants.CURRENT_KNOWN_SUBJECT)
        when(mockContext.getMember(Constants.CURRENT_KNOWN_SUBJECT)).thenReturn(mockUser);

        // Mock the HTTP servlet request
        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getHeader(Constants.USER_AGENT_HEADER)).thenReturn("Mozilla/5.0");
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn("127.0.0.1");

        TransientObjectWrapper<HttpServletRequestWrapper> transientObjectWrapper = mock(TransientObjectWrapper.class);
        when(transientObjectWrapper.getWrapped()).thenReturn(httpServletRequestWrapper);
        when(wrappedContext.getParameter(Constants.HTTP_SERVLET_REQUEST)).thenReturn(transientObjectWrapper);

        // Mock the IdentityGovernanceService response
        ConnectorConfig connectorConfig = mock(ConnectorConfig.class);
        Property property = new Property();
        property.setName(Constants.SIFT_API_KEY_PROP);
        property.setValue("dummyApiKey");
        when(connectorConfig.getProperties()).thenReturn(new Property[]{property});
        when(mockIdentityGovernanceService.getConnectorWithConfigs("carbon.super", Constants.CONNECTOR_NAME))
                .thenReturn(connectorConfig);

        List<String> paramKeys = Arrays.asList(Constants.USER_ID_KEY, Constants.USER_AGENT_KEY, Constants.IP_KEY,
                Constants.SESSION_ID_KEY);
        Map<String, Object> passedCustomParams = new HashMap<>();
        passedCustomParams.put("customKey", "customValue");

        JSONObject payload = Util.buildPayload(mockContext, "LOGIN_SUCCESS", paramKeys, passedCustomParams);

        assertEquals(payload.getString(Constants.TYPE), Constants.LOGIN_TYPE);
        assertEquals(payload.getString(Constants.LOGIN_STATUS), "$success");
        assertEquals(payload.getString("customKey"), "customValue");
    }

    @Test
    public void testGetPassedCustomParams() {

        Map<String, Object> paramMap = new HashMap<>();
        paramMap.put("key1", "value1");

        Map<String, Object> result = Util.getPassedCustomParams(new Object[]{paramMap});
        assertNotNull(result);
        assertEquals(result.get("key1"), "value1");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetPassedCustomParamsWithInvalidArgument() {

        Util.getPassedCustomParams(new Object[]{"invalidArgument"});
    }

    @Test
    public void testIsLoggingEnabled() {

        Map<String, Object> passedCustomParams = new HashMap<>();
        passedCustomParams.put(Constants.LOGGING_ENABLED, true);

        boolean result = Util.isLoggingEnabled(passedCustomParams);
        assertTrue(result);
    }

    @Test
    public void testIsLoggingEnabledWithNullParams() {

        boolean result = Util.isLoggingEnabled(null);
        assertFalse(result);
    }
}
