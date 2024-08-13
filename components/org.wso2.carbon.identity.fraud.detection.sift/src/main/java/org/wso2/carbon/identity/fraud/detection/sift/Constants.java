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

public class Constants {

    private Constants() {
    }

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
