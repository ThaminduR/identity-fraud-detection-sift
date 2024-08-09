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

package org.wso2.carbon.identity.fraud.sift.conditional.auth.functions;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.governance.IdentityGovernanceUtil.getPropertyObject;

public class SiftConfigConnector implements IdentityConnectorConfig {

    private static final String SIFT_ACCOUNT_ID = "sift.account.id";
    private static final String SIFT_API_KEY = "__secret__.sift.api.key"; // __secret__ prefix is used to mark the property as confidential for UI rendering.

    @Override
    public String getName() {

        return "sift-config";
    }

    @Override
    public String getFriendlyName() {

        return "Sift Configurations";
    }

    @Override
    public String getCategory() {

        return "Other Settings";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(SIFT_ACCOUNT_ID, "Account Id");
        mapping.put(SIFT_API_KEY, "API Key");
        return mapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(SIFT_ACCOUNT_ID, "Account id of the Sift account");
        mapping.put(SIFT_API_KEY, "API key of the Sift account");
        return mapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(SIFT_ACCOUNT_ID);
        properties.add(SIFT_API_KEY);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {

        Map<String, String> defaultProperties = new HashMap<>();

        defaultProperties.put(SIFT_ACCOUNT_ID, "");
        defaultProperties.put(SIFT_API_KEY, "");

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {

        return new HashMap<>();
    }

    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        List<String> properties = new ArrayList<>();
        properties.add(SIFT_API_KEY);
        return properties;
    }

    @Override
    public Map<String, Property> getMetaData() {

        Map<String, Property> meta = new HashMap<>();
        meta.put(SIFT_ACCOUNT_ID,
                getPropertyObject(IdentityMgtConstants.DataTypes.STRING.getValue()));
//        meta.put(SIFT_API_KEY,
//                getPropertyObject(IdentityMgtConstants.DataTypes.STRING.getValue()));

        return meta;
    }
}
