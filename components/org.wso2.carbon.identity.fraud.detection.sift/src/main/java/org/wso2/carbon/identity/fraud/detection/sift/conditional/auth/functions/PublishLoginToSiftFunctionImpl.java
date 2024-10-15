package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.graalvm.polyglot.HostAccess;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.util.Util;

import java.util.List;
import java.util.Map;

/**
 * Function to publish login event to Sift.
 */
public class PublishLoginToSiftFunctionImpl implements PublishLoginToSiftFunction {

    private static final Log LOG = LogFactory.getLog(PublishLoginToSiftFunctionImpl.class);
    private final CloseableHttpClient httpClient;

    public PublishLoginToSiftFunctionImpl(CloseableHttpClient httpClient) {

        this.httpClient = httpClient;
    }

    @Override
    @HostAccess.Export
    public void publishLoginEventInfoToSift(JsAuthenticationContext context, String loginStatus, List<String> paramKeys,
                                            Object... paramMap) throws FrameworkException {

        HttpPost request = new HttpPost(Constants.SIFT_API_URL);
        request.addHeader("Content-Type", "application/json");

        Map<String, Object> passedCustomParams = Util.getPassedCustomParams(paramMap);

        boolean isLoggingEnabled = Util.isLoggingEnabled(passedCustomParams);

        JSONObject payload = Util.buildPayload(context, loginStatus, paramKeys, passedCustomParams);
        if (isLoggingEnabled) {
            LOG.info("Payload sent to Sift for login event publishing: " + payload);
        }
        StringEntity entity = new StringEntity(payload.toString(), ContentType.APPLICATION_JSON);
        request.setEntity(entity);

        try (CloseableHttpResponse response = httpClient.execute(request)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                LOG.debug("Successfully published login event information to Sift.");
            } else {
                LOG.error("Error occurred while publishing login event information to Sift. Status code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (Exception e) {
            LOG.error("Error occurred while publishing login event information to Sift.", e);
        }
    }
}
