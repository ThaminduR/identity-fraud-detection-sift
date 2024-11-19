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

package org.wso2.carbon.identity.fraud.detection.sift;

/**
 * Constants class to hold the constants used in the Sift connector.
 */
public class Constants {

    private Constants() {
    }

    public static final String SIFT_API_URL = "https://encu6fvnqmd05.x.pipedream.net/";

    // Connector configs.
    public static final String SIFT_ACCOUNT_ID_PROP = "sift.account.id";
    public static final String SIFT_ACCOUNT_ID_PROP_NAME = "Account ID";
    public static final String SIFT_ACCOUNT_ID_PROP_DESC =  "Account id of the Sift account.";
    // __secret__ prefix is used to mark the property as confidential for UI rendering.
    public static final String SIFT_API_KEY_PROP = "__secret__.sift.api.key";
    public static final String SIFT_API_KEY_PROP_NAME = "API Key";
    public static final String SIFT_API_KEY_PROP_DESC = "API key of the Sift account.";
    public static final String CONNECTOR_NAME = "sift-configuration";
    public static final String CONNECTOR_FRIENDLY_NAME = "Sift Configuration";
    public static final String CONNECTOR_CATEGORY = "Other Settings";
    public static final String CONNECTOR_SUB_CATEGORY = "DEFAULT";
    public static final int CONNECTOR_ORDER = 0;

    // HTTP Client configs.
    // Timeouts in milliseconds.
    public static final int CONNECTION_TIMEOUT = 5000;
    public static final int CONNECTION_REQUEST_TIMEOUT = 5000;
    public static final int READ_TIMEOUT = 5000;

    // Identity configs.
    public static final String CONNECTION_TIMEOUT_CONFIG = "Sift.HTTPClient.ConnectionTimeout";
    public static final String CONNECTION_REQUEST_TIMEOUT_CONFIG = "Sift.HTTPClient.ConnectionRequestTimeout";
    public static final String READ_TIMEOUT_CONFIG = "Sift.HTTPClient.ReadTimeout";

    // Supported param keys.
    public static final String USER_ID_KEY = "$user_id";
    public static final String SESSION_ID_KEY = "$session_id";
    public static final String IP_KEY = "$ip";
    public static final String USER_AGENT_KEY = "$user_agent";

    /**
     * Enum to hold the login status.
     */
    public enum LoginStatus {

        LOGIN_SUCCESS("LOGIN_SUCCESS", "$success"),
        LOGIN_FAILED("LOGIN_FAILED", "$failure"),
        PRE_LOGIN("PRE_LOGIN", null); // Sift does not have a pre-login status.

        private final String status;
        private final String siftValue;

        // constructor
        LoginStatus(String status, String siftValue) {

            this.status = status;
            this.siftValue = siftValue;
        }

        // get status
        public String getStatus() {

            return status;
        }

        // get sift value
        public String getSiftValue() {

            return siftValue;
        }
    }
}
