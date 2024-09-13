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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.fraud.detection.sift.models.LoginEventPayload;

import java.util.Map;

public class LoginEventPayloadTest {

    @Test
    public void testToJsonWithValidFields() {

        LoginEventPayload payload = new LoginEventPayload();
        payload.setType("$login");
        payload.setApiKey("YOUR_API_KEY");
        payload.setUserId("12414-124124-124124-124124");
        payload.setLoginStatus("$success");
        payload.setSessionId("23432423-235325-2352-352");
        payload.setIp("128.148.1.135");

        LoginEventPayload.Browser browser = new LoginEventPayload.Browser();
        browser.setUserAgent("Mozilla/5.0");
        payload.setBrowser(browser);

        String jsonOutput = payload.toJson();

        validateJson(jsonOutput);
        Assert.assertTrue(jsonOutput.contains("\"$type\":\"$login\""));
        Assert.assertTrue(jsonOutput.contains("\"$api_key\":\"YOUR_API_KEY\""));
        Assert.assertTrue(jsonOutput.contains("\"$user_id\":\"12414-124124-124124-124124\""));
        Assert.assertTrue(jsonOutput.contains("\"$login_status\":\"$success\""));
        Assert.assertTrue(jsonOutput.contains("\"$session_id\":\"23432423-235325-2352-352\""));
        Assert.assertTrue(jsonOutput.contains("\"$ip\":\"128.148.1.135\""));
        Assert.assertTrue(jsonOutput.contains("\"$user_agent\":\"Mozilla/5.0\""));
    }

    @Test
    public void testToJsonWithArbitraryData() {

        LoginEventPayload payload = new LoginEventPayload();
        payload.setType("$login");
        payload.setApiKey("YOUR_API_KEY");

        // Adding arbitrary data.
        Map<String, Object> arbitraryData = Map.of(
                "$social_sign_on", "$linkedin",
                "$brand_name", "sift",
                "$site_domain", "sift.com"
        );
        payload.setArbitraryData(arbitraryData);
        String jsonOutput = payload.toJson();

        validateJson(jsonOutput);
        Assert.assertTrue(jsonOutput.contains("\"$social_sign_on\":\"$linkedin\""));
        Assert.assertTrue(jsonOutput.contains("\"$brand_name\":\"sift\""));
        Assert.assertTrue(jsonOutput.contains("\"$site_domain\":\"sift.com\""));
    }

    @Test
    public void testToJsonWithNullFields() {

        LoginEventPayload payload = new LoginEventPayload();
        // Leave fields as null and set only arbitrary data
        Map<String, Object> arbitraryData = Map.of(
                "$social_sign_on", "$linkedin"
        );
        payload.setArbitraryData(arbitraryData);
        String jsonOutput = payload.toJson();

        validateJson(jsonOutput);
        System.out.println(jsonOutput);
        Assert.assertFalse(jsonOutput.contains("$user_id"), "$user_id should not be present.");
        Assert.assertTrue(jsonOutput.contains("\"$social_sign_on\":\"$linkedin\""));
    }

    private void validateJson(String jsonOutput) {

        try {
            JsonParser.parseString(jsonOutput);
        } catch (JsonSyntaxException e) {
            Assert.fail("Invalid JSON format: " + jsonOutput);
        }
    }

    @Test
    public void testArbitraryDataIsNotNested() {

        LoginEventPayload payload = new LoginEventPayload();
        payload.setType("$login");
        payload.setApiKey("YOUR_API_KEY");

        // Adding arbitrary data
        Map<String, Object> arbitraryData = Map.of(
                "$social_sign_on", "$linkedin",
                "$brand_name", "sift",
                "$site_domain", "sift.com"
        );
        payload.setArbitraryData(arbitraryData);
        String jsonOutput = payload.toJson();

        // Validate that the output is valid JSON
        validateJson(jsonOutput);

        // Parse the JSON into a JsonObject
        JsonObject jsonObject = JsonParser.parseString(jsonOutput).getAsJsonObject();

        // Ensure that arbitrary data fields are at the root level.
        Assert.assertTrue(jsonObject.has("$social_sign_on"), "$social_sign_on should be at the root level.");
        Assert.assertTrue(jsonObject.has("$brand_name"), "$brand_name should be at the root level.");
        Assert.assertTrue(jsonObject.has("$site_domain"), "$site_domain should be at the root level.");

        // Ensure there is no "arbitraryData" field nesting the arbitrary data
        Assert.assertFalse(jsonObject.has("arbitraryData"), "arbitraryData should not be a nested object.");

        // Validate that fields from the base payload are also present
        Assert.assertTrue(jsonObject.has("$type"), "$type should be present.");
        Assert.assertTrue(jsonObject.has("$api_key"), "$api_key should be present.");
    }

    @Test
    public void testToJsonWithOverriddenArbitraryData() {

        LoginEventPayload payload = new LoginEventPayload();
        payload.setUserId("some_user_id");

        // Adding arbitrary data that includes some fields.
        Map<String, Object> arbitraryData = Map.of(
                "$user_id", "override_user_id",
                "$session_id", "override_session_id",
                "$ip", "192.168.1.1"
        );
        payload.setArbitraryData(arbitraryData);
        String jsonOutput = payload.toJson();

        validateJson(jsonOutput);
        Assert.assertTrue(jsonOutput.contains("\"$user_id\":\"override_user_id\""));
        Assert.assertTrue(jsonOutput.contains("\"$session_id\":\"override_session_id\""));
        Assert.assertTrue(jsonOutput.contains("\"$ip\":\"192.168.1.1\""));

        // Check for duplicate keys.
        JsonObject jsonObject = JsonParser.parseString(jsonOutput).getAsJsonObject();
        Assert.assertEquals(jsonObject.entrySet().stream().filter(e -> e.getKey().equals("$user_id")).count(), 1);
        Assert.assertEquals(jsonObject.entrySet().stream().filter(e -> e.getKey().equals("$session_id")).count(), 1);
    }
}
