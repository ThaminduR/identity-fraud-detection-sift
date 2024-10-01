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

package org.wso2.carbon.identity.fraud.detection.sift.models;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.Map;

/**
 * Represents the payload of a login event to be sent to Sift.
 */
public class LoginEventPayload {

    @SerializedName("$type")
    @Expose
    private String type = "$login";

    @SerializedName("$api_key")
    @Expose
    private String apiKey;

    @SerializedName("$user_id")
    @Expose
    private String userId;

    @SerializedName("$login_status")
    @Expose
    private String loginStatus;

    @SerializedName("$session_id")
    @Expose
    private String sessionId;

    @SerializedName("$ip")
    @Expose
    private String ip;

    @SerializedName("$browser")
    @Expose
    private Browser browser;

    /* Field for the user-provided arbitrary JSON data.
     Mark arbitraryData without @Expose to prevent its serialization.*/
    private Map<String, Object> arbitraryData;

    /**
     * Represents the browser details.
     */
    public static class Browser {

        @SerializedName("$user_agent")
        @Expose
        private String userAgent;

        public String getUserAgent() {

            return userAgent;
        }

        public void setUserAgent(String userAgent) {

            this.userAgent = userAgent;
        }
    }

    public String getType() {

        return type;
    }

    public void setType(String type) {

        this.type = type;
    }

    public String getApiKey() {

        return apiKey;
    }

    public void setApiKey(String apiKey) {

        this.apiKey = apiKey;
    }

    public String getUserId() {

        return userId;
    }

    public void setUserId(String userId) {

        this.userId = userId;
    }

    public String getLoginStatus() {

        return loginStatus;
    }

    public void setLoginStatus(String loginStatus) {

        this.loginStatus = loginStatus;
    }

    public String getSessionId() {

        return sessionId;
    }

    public void setSessionId(String sessionId) {

        this.sessionId = sessionId;
    }

    public String getIp() {

        return ip;
    }

    public void setIp(String ip) {

        this.ip = ip;
    }

    public Browser getBrowser() {

        return browser;
    }

    public void setBrowser(Browser browser) {

        this.browser = browser;
    }

    public Map<String, Object> getArbitraryData() {

        return arbitraryData;
    }

    public void setArbitraryData(Map<String, Object> arbitraryData) {

        this.arbitraryData = arbitraryData;
    }

    /**
     * Serialize the object to JSON.
     *
     * @return JSON string
     */
    public String toJson() {

        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        JsonObject rootJson = gson.toJsonTree(this).getAsJsonObject();

        // Add arbitrary data directly to the root.
        if (this.arbitraryData != null) {
            for (Map.Entry<String, Object> entry : this.arbitraryData.entrySet()) {
                rootJson.add(entry.getKey(), gson.toJsonTree(entry.getValue()));
            }
        }

        return gson.toJson(rootJson);
    }
}

