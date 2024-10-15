package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.util.ArrayList;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PublishLoginToSiftFunctionImplTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private HttpEntity httpEntity;

    @InjectMocks
    private PublishLoginToSiftFunctionImpl publishLoginToSiftFunction;

    @BeforeClass
    public void setUp() throws FrameworkException {

        MockitoAnnotations.openMocks(this);
        // Mocking Util methods
        mockStatic(Util.class);
        when(Util.getPassedCustomParams(any())).thenReturn(new HashMap<>());
        when(Util.isLoggingEnabled(any())).thenReturn(true);
        when(Util.buildPayload(any(), anyString(), anyList(), anyMap())).thenReturn(new JSONObject());
    }

    @Test(priority = 0)
    public void testPublishLoginEventInfoToSift_Success() throws Exception {

        // Mocking the response
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

        // Calling the method
        publishLoginToSiftFunction.publishLoginEventInfoToSift(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        // Verifying the interactions
        verify(httpClient, times(1)).execute(any(HttpPost.class));
    }

    @Test(priority = 1)
    public void testPublishLoginEventInfoToSift_ErrorResponse() throws Exception {

        // Mocking the response
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);

        // Calling the method
        publishLoginToSiftFunction.publishLoginEventInfoToSift(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        // Verifying the interactions
        verify(httpClient, times(2)).execute(any(HttpPost.class));
    }

    @Test(priority = 2)
    public void testPublishLoginEventInfoToSift_Exception() throws Exception {

        // Mocking the response to throw an exception
        when(httpClient.execute(any(HttpPost.class))).thenThrow(new RuntimeException("Test Exception"));

        // Calling the method
        publishLoginToSiftFunction.publishLoginEventInfoToSift(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        // Verifying the interactions
        verify(httpClient, times(3)).execute(any(HttpPost.class));
    }
}
