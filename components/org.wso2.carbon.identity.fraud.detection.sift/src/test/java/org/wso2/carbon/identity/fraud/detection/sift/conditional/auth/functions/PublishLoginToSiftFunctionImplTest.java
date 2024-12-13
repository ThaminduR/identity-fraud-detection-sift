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
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for PublishLoginToSiftFunctionImpl class.
 */
public class PublishLoginToSiftFunctionImplTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private HttpEntity httpEntity;

    @InjectMocks
    private PublishLoginToSiftFunctionImpl publishLoginToSiftFunction;

    private MockedStatic<Util> utilMockedStatic;

    private ByteArrayOutputStream logOutput;

    @BeforeClass
    public void setUp() throws FrameworkException {

        MockitoAnnotations.openMocks(this);
        utilMockedStatic = mockStatic(Util.class);
        when(Util.getPassedCustomParams(any())).thenReturn(new HashMap<>());
        when(Util.isLoggingEnabled(any())).thenReturn(true);
        when(Util.buildPayload(any(), anyString(), anyMap())).thenReturn(new JSONObject());
    }

    @BeforeMethod
    public void redirectOutputStreams() {

        // Redirect System.out to capture logs.
        logOutput = new ByteArrayOutputStream();
        System.setOut(new PrintStream(logOutput));
    }

    @AfterClass
    public void tearDown() {

        utilMockedStatic.close();
    }

    @Test()
    public void testPublishLoginEventToSiftSuccess() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpResponse.getEntity()).thenReturn(httpEntity);
        when(httpEntity.getContent())
                .thenReturn(new ByteArrayInputStream("{\"status\":0}".getBytes(StandardCharsets.UTF_8)));

        publishLoginToSiftFunction.publishLoginEventToSift(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        Assert.assertTrue(logOutput.toString().contains("Successfully published login event information to Sift."));
    }

    @Test()
    public void testPublishLoginEventToSiftSiftError() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpResponse.getEntity()).thenReturn(httpEntity);
        when(httpEntity.getContent())
                .thenReturn(new ByteArrayInputStream("{\"status\":1}".getBytes(StandardCharsets.UTF_8)));

        publishLoginToSiftFunction.publishLoginEventToSift(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        Assert.assertTrue(logOutput.toString().contains("Error occurred from Sift while publishing login event" +
                " information. Received Sift status: 1"));
    }

    @Test()
    public void testPublishLoginEventToSiftErrorResponse() throws Exception {

        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        StatusLine statusLine = mock(StatusLine.class);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);

        publishLoginToSiftFunction.publishLoginEventToSift(
                mock(JsAuthenticationContext.class), "LOGIN_SUCCESS", new ArrayList<>(),
                new HashMap<String, Object>());

        Assert.assertTrue(logOutput.toString().contains("Error occurred while publishing login event information" +
                " to Sift. HTTP Status code: 500"));

    }
}
