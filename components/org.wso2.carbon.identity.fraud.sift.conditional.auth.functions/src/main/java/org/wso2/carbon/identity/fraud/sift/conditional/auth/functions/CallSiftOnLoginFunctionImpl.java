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

import org.graalvm.polyglot.HostAccess;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.fraud.sift.conditional.auth.functions.internal.SiftConditionalFunctionsDataHolder;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class CallSiftOnLoginFunctionImpl implements CallSiftOnLoginFunction {

//    @Override
//    @HostAccess.Export
//    public double getSiftRiskScoreForLogin(JsAuthenticationContext context) {
//
//        System.out.println("Inside the CallSiftOnLoginFunctionImpl");
//        return 0.7;
//    }

    @Override
    @HostAccess.Export
    public double getSiftRiskScoreForLogin(JsAuthenticationContext context, String loginStatus, List<String> parameters,
                                           Object... paramMap)  throws FrameworkException{


        Map<String,String> props = getSiftConfigs(context.getWrapped().getTenantDomain());

        // print props
        for (Map.Entry<String, String> entry : props.entrySet()) {
            System.out.println(entry.getKey() + ":" + entry.getValue());
        }

        Map<String, Object> passedcustomparams = null;
        JSONObject pmap = new JSONObject();
        if (paramMap.length == 1) {
            if (paramMap[0] instanceof Map) {
                passedcustomparams = (Map<String, Object>) paramMap[0];
            } else {
                throw new IllegalArgumentException("Invalid argument type. Expected paramMap " +
                        "(Map<String, Object>).");
            }
        }



        if (passedcustomparams != null) {
            System.out.println("Passed custom parameters: " + passedcustomparams);
            pmap = new JSONObject(passedcustomparams);
        }

        System.out.println("Inside the CallSiftOnLoginFunctionImpl");
        return 0.7;
    }

    private String getAccountId (String tenantDomain) throws FrameworkException {

        return getSiftConfigs(tenantDomain).get("sift.account.id");
    }

    private String getApiKey (String tenantDomain) throws FrameworkException {

        return getSiftConfigs(tenantDomain).get("sift.api.key");
    }

    Map<String, String> getSiftConfigs(String tenantDomain) throws FrameworkException {

        try {
            ConnectorConfig connectorConfig =
                    getIdentityGovernanceService().getConnectorWithConfigs(tenantDomain, "sift-config");
            if (connectorConfig == null) {
                throw new FrameworkException("Sift configurations not found for tenant: " + tenantDomain);
            }
            Map<String, String> siftConfigs = new HashMap<>();
            // go through the connector config and get the sift configurations
            for (Property prop: connectorConfig.getProperties()) {
                siftConfigs.put(prop.getName(), prop.getValue());
            }



            return siftConfigs;
        } catch (IdentityGovernanceException e) {
            throw new FrameworkException("Error while retreiving sift configurations: "+ e.getMessage());
        }


    }

    private IdentityGovernanceService getIdentityGovernanceService() {

        return SiftConditionalFunctionsDataHolder.getInstance().getIdentityGovernanceService();
    }
}
