package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class CallSiftOnLoginFunctionImplTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private HttpEntity httpEntity;

    @InjectMocks
    private CallSiftOnLoginFunctionImpl callSiftOnLoginFunction;

    @BeforeClass
    public void setUp() throws FrameworkException {

        MockitoAnnotations.openMocks(this);
        // Mocking Util methods
        mockStatic(Util.class);
        when(Util.getPassedCustomParams(any())).thenReturn(new HashMap<>());
        when(Util.isLoggingEnabled(any())).thenReturn(true);
        when(Util.buildPayload(any(), anyString(), anyList(), anyMap())).thenReturn(new JSONObject());
    }

    @Test
    public void testGetSiftRiskScoreForLogin_Success() throws Exception {

        // Mocking the response
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        JSONObject jsonResponse = new JSONObject();
        jsonResponse.put(Constants.SIFT_STATUS, Constants.SIFT_STATUS_OK);
        JSONObject scoreResponse = new JSONObject();
        JSONObject scores = new JSONObject();
        JSONObject accountTakeover = new JSONObject();
        accountTakeover.put(Constants.SIFT_SCORE, 0.85);
        scores.put(Constants.SIFT_ACCOUNT_TAKEOVER, accountTakeover);
        scoreResponse.put(Constants.SIFT_SCORES, scores);
        jsonResponse.put(Constants.SIFT_SCORE_RESPONSE, scoreResponse);

        when(httpEntity.getContent()).thenReturn(new StringEntity(jsonResponse.toString(), StandardCharsets.UTF_8)
                .getContent());

        // Calling the method
        double riskScore = callSiftOnLoginFunction.getSiftRiskScoreForLogin(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        // Asserting the result
        assertEquals(riskScore, 0.85);
    }

    @Test
    public void testGetSiftRiskScoreForLogin_ErrorResponse() throws Exception {

        // Mocking the response
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        // Calling the method
        double riskScore = callSiftOnLoginFunction.getSiftRiskScoreForLogin(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        // Asserting the result
        assertEquals(riskScore, 1.0);
    }

    @Test
    public void testGetSiftRiskScoreForLogin_Exception() throws Exception {

        // Mocking the response
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        // Calling the method
        double riskScore = callSiftOnLoginFunction.getSiftRiskScoreForLogin(
                mock(JsAuthenticationContext.class), "SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        // Asserting the result
        assertEquals(riskScore, 1.0);
    }
}
