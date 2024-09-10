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

package org.wso2.carbon.identity.fraud.detection;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.models.ConnectionConfig;

/**
 * Test class for ConnectionConfig.
 */
public class ConnectionConfigTest {

    @Test
    public void testBuilderWithPassedValues() {

        ConnectionConfig config = new ConnectionConfig.Builder()
                .setConnectionTimeout(5000)
                .setReadTimeout(6000)
                .setConnectionRequestTimeout(7000)
                .build();

        Assert.assertEquals(config.getConnectionTimeout(), 5000);
        Assert.assertEquals(config.getReadTimeout(), 6000);
        Assert.assertEquals(config.getConnectionRequestTimeout(), 7000);
    }

    @Test
    public void testBuilderWithIdentityUtilValues() {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class)) {
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_TIMEOUT_CONFIG))
                    .thenReturn("8000");
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.READ_TIMEOUT_CONFIG))
                    .thenReturn("9000");
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_REQUEST_TIMEOUT_CONFIG))
                    .thenReturn("10000");

            ConnectionConfig config = new ConnectionConfig.Builder().build();

            Assert.assertEquals(config.getConnectionTimeout(), 8000);
            Assert.assertEquals(config.getReadTimeout(), 9000);
            Assert.assertEquals(config.getConnectionRequestTimeout(), 10000);
        }
    }

    @Test
    public void testBuilderWithInvalidIdentityUtilValues() {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class)) {
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_TIMEOUT_CONFIG))
                    .thenReturn("invalid");
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.READ_TIMEOUT_CONFIG))
                    .thenReturn("invalid");
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.CONNECTION_REQUEST_TIMEOUT_CONFIG))
                    .thenReturn("invalid");

            ConnectionConfig config = new ConnectionConfig.Builder().build();

            Assert.assertEquals(config.getConnectionTimeout(), Constants.CONNECTION_TIMEOUT);
            Assert.assertEquals(config.getReadTimeout(), Constants.READ_TIMEOUT);
            Assert.assertEquals(config.getConnectionRequestTimeout(), Constants.CONNECTION_REQUEST_TIMEOUT);
        }
    }

    @Test
    public void testBuilderWithNoValuesPassed() {

        ConnectionConfig config = new ConnectionConfig.Builder().build();

        Assert.assertEquals(config.getConnectionTimeout(), Constants.CONNECTION_TIMEOUT);
        Assert.assertEquals(config.getReadTimeout(), Constants.READ_TIMEOUT);
        Assert.assertEquals(config.getConnectionRequestTimeout(), Constants.CONNECTION_REQUEST_TIMEOUT);
    }
}
