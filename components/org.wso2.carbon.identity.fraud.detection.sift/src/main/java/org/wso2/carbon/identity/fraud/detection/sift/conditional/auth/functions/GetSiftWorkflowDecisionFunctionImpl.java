/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.graalvm.polyglot.HostAccess;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.wso2.carbon.identity.fraud.detection.sift.util.Util.getMaskedSiftPayload;

/**
 * Function to get Sift workflow status.
 */
public class GetSiftWorkflowDecisionFunctionImpl implements GetSiftWorkflowDecisionFunction {

    private static final Log LOG = LogFactory.getLog(GetSiftWorkflowDecisionFunctionImpl.class);
    private final CloseableHttpClient httpClient;

    public GetSiftWorkflowDecisionFunctionImpl(CloseableHttpClient httpClient) {

        this.httpClient = httpClient;
    }

    @Override
    @HostAccess.Export
    public String getSiftWorkFlowDecision(JsAuthenticationContext context, String loginStatus, Object... paramMap)
            throws FrameworkException {

        HttpPost request = new HttpPost(Constants.SIFT_API_URL + Constants.RETURN_WORKFLOW_PARAM);
        request.addHeader(Constants.CONTENT_TYPE_HEADER, FrameworkConstants.ContentTypes.TYPE_APPLICATION_JSON);

        Map<String, Object> passedCustomParams = Util.getPassedCustomParams(paramMap);

        boolean isLoggingEnabled = Util.isLoggingEnabled(passedCustomParams);

        JSONObject payload = Util.buildPayload(context, loginStatus, passedCustomParams);

        if (isLoggingEnabled) {
            LOG.info("Payload sent to Sift for workflow execution: " + getMaskedSiftPayload(payload));
        }

        StringEntity entity = new StringEntity(payload.toString(), ContentType.APPLICATION_JSON);
        request.setEntity(entity);

        try (CloseableHttpResponse response = httpClient.execute(request)) {

            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                LOG.error("Error occurred while getting the workflow status from Sift. HTTP Status code: " +
                        response.getStatusLine().getStatusCode());
                return null;
            }

            HttpEntity responseEntity = response.getEntity();
            if (responseEntity == null) {
                LOG.error("Error occurred while getting the workflow status from Sift. Response is null.");
                return null;
            }

            JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(
                    response.getEntity().getContent(), StandardCharsets.UTF_8)));
            if (jsonResponse.has(Constants.SIFT_STATUS) &&
                    jsonResponse.getInt(Constants.SIFT_STATUS) != Constants.SIFT_STATUS_OK) {
                LOG.error("Error occurred from Sift while getting the workflow status. Received Sift status: " +
                        jsonResponse.getInt(Constants.SIFT_STATUS));
                return null;
            }

            JSONObject scoreResponse = jsonResponse.optJSONObject(Constants.SIFT_SCORE_RESPONSE);
            JSONArray workflowStatuses = scoreResponse != null ?
                    scoreResponse.optJSONArray(Constants.SIFT_WORKFLOW_STATUSES) : null;
            if (workflowStatuses != null && workflowStatuses.length() > 0) {
                for (int i = 0; i < workflowStatuses.length(); i++) {
                    JSONObject workflowStatus = workflowStatuses.optJSONObject(i);
                    if (isATOAbuseType(workflowStatus) && isSessionType(workflowStatus)) {
                        String workflowStatusId = getDecision(workflowStatus);
                        if (isLoggingEnabled) {
                            LOG.info("Sift workflow decision id: " + workflowStatusId);
                        }
                        return workflowStatusId;
                    }
                }
            }

        } catch (IOException e) {
            throw new FrameworkException("Error while executing the request: " + e);
        }
        return null;
    }

    private boolean isATOAbuseType(JSONObject workflowStatus) {

        JSONArray abuseTypes = workflowStatus.optJSONArray(Constants.SIFT_ABUSE_TYPES);
        for (int i = 0; i < abuseTypes.length(); i++) {
            String abuseType = abuseTypes.optString(i);
            if (Constants.SIFT_ACCOUNT_TAKEOVER.equals(abuseType)) {
                return true;
            }
        }
        return false;
    }

    private boolean isSessionType(JSONObject workflowStatus) {

        JSONObject entity = workflowStatus.optJSONObject(Constants.SIFT_ENTITY);
        if (entity == null) {
            return false;
        }
        String type = entity.optString(Constants.SIFT_TYPE);
        return Constants.SIFT_SESSION.equals(type);
    }

    private String getDecision(JSONObject workflowStatus) {

        JSONArray history = workflowStatus.optJSONArray(Constants.SIFT_HISTORY);
        if (history == null) {
            return null;
        }
        for (int i = 0; i < history.length(); i++) {
            JSONObject historyItem = history.optJSONObject(i);
            if (historyItem != null && historyItem.has(Constants.SIFT_APP)
                    && Constants.SIFT_DECISION.equals(historyItem.getString(Constants.SIFT_APP))) {
                JSONObject config = historyItem.optJSONObject(Constants.SIFT_CONFIG);
                if (config != null && config.has(Constants.SIFT_DECISION_ID)) {
                    return config.getString(Constants.SIFT_DECISION_ID);
                }
            }
        }
        return null;
    }

}
