/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.fraud.detection.sift.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.json.JSONObject;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
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
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Util class test cases.
 */
public class UtilTest {

    public static final String USER_ID = "user123";
    public static final String SESSION_ID = "session123";
    public static final String IP_ADDRESS = "127.0.0.1";
    public static final String USER_AGENT = "Mozilla/5.0";
    public static final String CUSTOM_USER_ID = "customUserId";
    public static final String CUSTOM_KEY = "customKey";
    public static final String CUSTOM_VALUE = "customValue";
    public static final String CUSTOM_IP_ADDRESS = "192.168.8.1";
    public static final String CUSTOM_USER_AGENT = "customUserAgent";

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
    public void testBuildDefaultPayload() throws FrameworkException, IdentityGovernanceException,
            UserIdNotFoundException {

        AuthenticationContext wrappedContext = mock(AuthenticationContext.class);
        when(mockContext.getWrapped()).thenReturn(wrappedContext);

        when(mockContext.getWrapped().getTenantDomain()).thenReturn("carbon.super");
        when(mockContext.getWrapped().getContextIdentifier()).thenReturn(SESSION_ID);

        JsGraalAuthenticatedUser mockUser = mock(JsGraalAuthenticatedUser.class);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(mockUser.getWrapped()).thenReturn(authenticatedUser);
        when(mockUser.getWrapped().getUserId()).thenReturn(USER_ID);

        when(mockContext.getMember(Constants.CURRENT_KNOWN_SUBJECT)).thenReturn(mockUser);

        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getHeader(Constants.USER_AGENT_HEADER)).thenReturn(USER_AGENT);
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn(IP_ADDRESS);

        TransientObjectWrapper<HttpServletRequestWrapper> transientObjectWrapper = mock(TransientObjectWrapper.class);
        when(transientObjectWrapper.getWrapped()).thenReturn(httpServletRequestWrapper);
        when(wrappedContext.getParameter(Constants.HTTP_SERVLET_REQUEST)).thenReturn(transientObjectWrapper);

        ConnectorConfig connectorConfig = mock(ConnectorConfig.class);
        Property property = new Property();
        property.setName(Constants.SIFT_API_KEY_PROP);
        property.setValue("dummyApiKey");
        when(connectorConfig.getProperties()).thenReturn(new Property[]{property});
        when(mockIdentityGovernanceService.getConnectorWithConfigs("carbon.super", Constants.CONNECTOR_NAME))
                .thenReturn(connectorConfig);

        HashMap<String, Object> passedCustomParams = new HashMap<>();

        JSONObject payload = Util.buildPayload(mockContext, "LOGIN_SUCCESS", passedCustomParams);
        assertEquals(payload.getString(Constants.TYPE), Constants.LOGIN_TYPE);
        assertEquals(payload.getString(Constants.LOGIN_STATUS), "$success");
        assertEquals(payload.getString(Constants.USER_ID_KEY), DigestUtils.sha256Hex(USER_ID));
        assertEquals(payload.getString(Constants.SESSION_ID_KEY), DigestUtils.sha256Hex(SESSION_ID));
        assertEquals(payload.getString(Constants.IP_KEY), IP_ADDRESS);
        assertEquals(payload.getJSONObject(Constants.BROWSER_KEY).getString(Constants.USER_AGENT_KEY), USER_AGENT);
    }

    /*
     * Test the buildPayload method with a custom user ID and an empty IP address and session id.
     */
    @Test
    public void testBuildModifiedPayload() throws FrameworkException, IdentityGovernanceException,
            UserIdNotFoundException {

        AuthenticationContext wrappedContext = mock(AuthenticationContext.class);
        when(mockContext.getWrapped()).thenReturn(wrappedContext);

        when(mockContext.getWrapped().getTenantDomain()).thenReturn("carbon.super");
        when(mockContext.getWrapped().getContextIdentifier()).thenReturn(SESSION_ID);

        JsGraalAuthenticatedUser mockUser = mock(JsGraalAuthenticatedUser.class);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(mockUser.getWrapped()).thenReturn(authenticatedUser);
        when(mockUser.getWrapped().getUserId()).thenReturn(USER_ID);

        when(mockContext.getMember(Constants.CURRENT_KNOWN_SUBJECT)).thenReturn(mockUser);

        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getHeader(Constants.USER_AGENT_HEADER)).thenReturn(USER_AGENT);
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn(IP_ADDRESS);

        TransientObjectWrapper<HttpServletRequestWrapper> transientObjectWrapper = mock(TransientObjectWrapper.class);
        when(transientObjectWrapper.getWrapped()).thenReturn(httpServletRequestWrapper);
        when(wrappedContext.getParameter(Constants.HTTP_SERVLET_REQUEST)).thenReturn(transientObjectWrapper);

        ConnectorConfig connectorConfig = mock(ConnectorConfig.class);
        Property property = new Property();
        property.setName(Constants.SIFT_API_KEY_PROP);
        property.setValue("dummyApiKey");
        when(connectorConfig.getProperties()).thenReturn(new Property[]{property});
        when(mockIdentityGovernanceService.getConnectorWithConfigs("carbon.super", Constants.CONNECTOR_NAME))
                .thenReturn(connectorConfig);

        HashMap<String, Object> passedCustomParams = new HashMap<>();
        passedCustomParams.put(CUSTOM_KEY, CUSTOM_VALUE);
        passedCustomParams.put(Constants.USER_ID_KEY, CUSTOM_USER_ID);
        passedCustomParams.put(Constants.IP_KEY, "");
        passedCustomParams.put(Constants.SESSION_ID_KEY, "");
        passedCustomParams.put(Constants.LOGGING_ENABLED, true);

        JSONObject payload = Util.buildPayload(mockContext, "LOGIN_FAILED", passedCustomParams);
        assertEquals(payload.getString(Constants.TYPE), Constants.LOGIN_TYPE);
        assertEquals(payload.getString(Constants.LOGIN_STATUS), "$failure");
        assertEquals(payload.getString(Constants.USER_ID_KEY), CUSTOM_USER_ID);
        assertTrue(payload.isNull(Constants.SESSION_ID_KEY));
        assertTrue(payload.isNull(Constants.IP_KEY));
        assertEquals(payload.getJSONObject(Constants.BROWSER_KEY).getString(Constants.USER_AGENT_KEY), USER_AGENT);
        assertEquals(payload.getString(CUSTOM_KEY), CUSTOM_VALUE);
    }

    /*
     * Test the buildPayload method with a replaced IP address and user agent.
     */
    @Test
    public void testBuildReplacedPayload() throws FrameworkException, IdentityGovernanceException,
            UserIdNotFoundException {

        AuthenticationContext wrappedContext = mock(AuthenticationContext.class);
        when(mockContext.getWrapped()).thenReturn(wrappedContext);

        when(mockContext.getWrapped().getTenantDomain()).thenReturn("carbon.super");
        when(mockContext.getWrapped().getContextIdentifier()).thenReturn(SESSION_ID);

        JsGraalAuthenticatedUser mockUser = mock(JsGraalAuthenticatedUser.class);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(mockUser.getWrapped()).thenReturn(authenticatedUser);
        when(mockUser.getWrapped().getUserId()).thenReturn(USER_ID);

        when(mockContext.getMember(Constants.CURRENT_KNOWN_SUBJECT)).thenReturn(mockUser);

        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getHeader(Constants.USER_AGENT_HEADER)).thenReturn(USER_AGENT);
        when(httpServletRequestWrapper.getRemoteAddr()).thenReturn(IP_ADDRESS);

        TransientObjectWrapper<HttpServletRequestWrapper> transientObjectWrapper = mock(TransientObjectWrapper.class);
        when(transientObjectWrapper.getWrapped()).thenReturn(httpServletRequestWrapper);
        when(wrappedContext.getParameter(Constants.HTTP_SERVLET_REQUEST)).thenReturn(transientObjectWrapper);

        ConnectorConfig connectorConfig = mock(ConnectorConfig.class);
        Property property = new Property();
        property.setName(Constants.SIFT_API_KEY_PROP);
        property.setValue("dummyApiKey");
        when(connectorConfig.getProperties()).thenReturn(new Property[]{property});
        when(mockIdentityGovernanceService.getConnectorWithConfigs("carbon.super", Constants.CONNECTOR_NAME))
                .thenReturn(connectorConfig);

        HashMap<String, Object> passedCustomParams = new HashMap<>();
        passedCustomParams.put(CUSTOM_KEY, CUSTOM_VALUE);
        passedCustomParams.put(Constants.IP_KEY, CUSTOM_IP_ADDRESS);
        passedCustomParams.put(Constants.USER_AGENT_KEY, CUSTOM_USER_AGENT);
        passedCustomParams.put(Constants.LOGGING_ENABLED, true);

        JSONObject payload = Util.buildPayload(mockContext, "LOGIN_SUCCESS", passedCustomParams);
        assertEquals(payload.getString(Constants.TYPE), Constants.LOGIN_TYPE);
        assertEquals(payload.getString(Constants.LOGIN_STATUS), "$success");
        assertEquals(payload.getString(Constants.USER_ID_KEY), DigestUtils.sha256Hex(USER_ID));
        assertEquals(payload.getString(Constants.SESSION_ID_KEY), DigestUtils.sha256Hex(SESSION_ID));
        assertEquals(payload.getString(Constants.IP_KEY), CUSTOM_IP_ADDRESS);
        assertEquals(payload.getJSONObject(Constants.BROWSER_KEY)
                .getString(Constants.USER_AGENT_KEY), CUSTOM_USER_AGENT);
        assertEquals(payload.getString(CUSTOM_KEY), CUSTOM_VALUE);
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

    @Test
    public void testGetMaskedSiftPayload() {

        // Create a sample payload with an API key.
        JSONObject payload = new JSONObject();
        payload.put("key1", "value1");
        payload.put(Constants.API_KEY, "12345abcde");

        String maskedPayload = Util.getMaskedSiftPayload(payload);

        JSONObject result = new JSONObject(maskedPayload);

        // Verify that the API key is masked correctly.
        String expectedMaskedApiKey = "12345*****";
        Assert.assertEquals(result.getString(Constants.API_KEY), expectedMaskedApiKey);

        // Verify that other keys are unchanged.
        Assert.assertEquals(result.getString("key1"), "value1");
    }


}
