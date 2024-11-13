package org.wso2.carbon.identity.fraud.detection.sift.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.fraud.detection.sift.Constants;
import org.wso2.carbon.identity.fraud.detection.sift.internal.SiftDataHolder;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.wso2.carbon.identity.fraud.detection.sift.Constants.CONNECTOR_NAME;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.HTTP_SERVLET_REQUEST;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.LOGIN_TYPE;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.SIFT_API_KEY_PROP;
import static org.wso2.carbon.identity.fraud.detection.sift.Constants.USER_AGENT_HEADER;

/**
 * Util class to build the payload to be sent to Sift.
 */
public class Util {

    private static final Log LOG = LogFactory.getLog(Util.class);

    public static JSONObject buildPayload(JsAuthenticationContext context, String loginStatus, List<String> paramKeys,
                                          Map<String, Object> passedCustomParams)
            throws FrameworkException {

        String loginSts = getLoginStatus(loginStatus).getSiftValue();

        JSONObject payload = new JSONObject();
        payload.put(Constants.TYPE, LOGIN_TYPE);
        payload.put(Constants.API_KEY, getSiftApiKey(context.getWrapped().getTenantDomain()));
        payload.put(Constants.LOGIN_STATUS, loginSts);

        if (paramKeys.contains(Constants.USER_ID_KEY)) {
            payload.put(Constants.USER_ID_KEY, resolvePayloadData(Constants.USER_ID_KEY, context));
        }

        if (paramKeys.contains(Constants.USER_AGENT_KEY)) {
            Map<String, String> browserProperties = new HashMap<>();
            browserProperties.put(Constants.USER_AGENT_KEY, resolvePayloadData(Constants.USER_AGENT_KEY, context));
            payload.put(Constants.BROWSER_KEY, browserProperties);
        }

        if (paramKeys.contains(Constants.IP_KEY)) {
            payload.put(Constants.IP_KEY, resolvePayloadData(Constants.IP_KEY, context));
        }

        if (paramKeys.contains(Constants.SESSION_ID_KEY)) {
            payload.put(Constants.SESSION_ID_KEY, resolvePayloadData(Constants.SESSION_ID_KEY, context));
        }

        if (passedCustomParams != null) {
            for (Map.Entry<String, Object> entry : passedCustomParams.entrySet()) {
                payload.put(entry.getKey(), entry.getValue());
            }
        }
        return payload;
    }

    public static Map<String, Object> getPassedCustomParams(Object[] paramMap) {

        Map<String, Object> passedcustomparams = null;
        if (paramMap.length == 1) {
            if (paramMap[0] instanceof Map) {
                passedcustomparams = (Map<String, Object>) paramMap[0];
            } else {
                throw new IllegalArgumentException("Invalid argument type. Expected paramMap " +
                        "(Map<String, Object>).");
            }
        }
        return passedcustomparams;
    }

    private static String getSiftApiKey(String tenantDomain) throws FrameworkException {

        String apiKey = getSiftConfigs(tenantDomain).get(SIFT_API_KEY_PROP);
        if (apiKey == null) {
            throw new FrameworkException("Sift API key not found for tenant: " + tenantDomain);
        }
        return apiKey;
    }

    static Map<String, String> getSiftConfigs(String tenantDomain) throws FrameworkException {

        try {
            ConnectorConfig connectorConfig =
                    getIdentityGovernanceService().getConnectorWithConfigs(tenantDomain, CONNECTOR_NAME);
            if (connectorConfig == null) {
                throw new FrameworkException("Sift configurations not found for tenant: " + tenantDomain);
            }
            Map<String, String> siftConfigs = new HashMap<>();
            // Go through the connector config and get the sift configurations.
            for (Property prop : connectorConfig.getProperties()) {
                siftConfigs.put(prop.getName(), prop.getValue());
            }

            return siftConfigs;
        } catch (IdentityGovernanceException e) {
            throw new FrameworkException("Error while retrieving sift configurations: " + e.getMessage());
        }

    }

    private static IdentityGovernanceService getIdentityGovernanceService() {

        return SiftDataHolder.getInstance().getIdentityGovernanceService();
    }

    // get login status from string
    private static Constants.LoginStatus getLoginStatus(String status) {

        if (Constants.LoginStatus.LOGIN_SUCCESS.getStatus().equalsIgnoreCase(status)) {
            return Constants.LoginStatus.LOGIN_SUCCESS;
        } else if (Constants.LoginStatus.LOGIN_FAILED.getStatus().equalsIgnoreCase(status)) {
            return Constants.LoginStatus.LOGIN_FAILED;
        } else {
            throw new IllegalArgumentException("Invalid login status: " + status);
        }
    }

    private static String resolvePayloadData(String key, JsAuthenticationContext context) throws FrameworkException {

        switch (key) {
            case Constants.USER_ID_KEY:
                return getUserId(context);
            case Constants.USER_AGENT_KEY:
                return getUserAgent(context);
            case Constants.IP_KEY:
                return getIpAddress(context);
            case Constants.SESSION_ID_KEY:
                return generateSessionHash(context);
            default:
                return null;
        }
    }

    private static String getUserId(JsAuthenticationContext context) {

        try {
            return ((JsGraalAuthenticatedUser) context.getMember(Constants.CURRENT_KNOWN_SUBJECT))
                    .getWrapped().getUserId();
        } catch (UserIdNotFoundException e) {
            LOG.debug("Unable to resolve the user id.", e);
            return null;
        }
    }

    private static String getUserAgent(JsAuthenticationContext context) {

        Object httpServletRequest = ((TransientObjectWrapper<?>) context.getWrapped().getParameter
                (HTTP_SERVLET_REQUEST)).getWrapped();
        if (httpServletRequest instanceof HttpServletRequestWrapper) {
            HttpServletRequestWrapper httpServletRequestWrapper = (HttpServletRequestWrapper) httpServletRequest;
            return httpServletRequestWrapper.getHeader(USER_AGENT_HEADER);
        }
        return null;
    }

    private static String getIpAddress(JsAuthenticationContext context) {

        Object httpServletRequest = ((TransientObjectWrapper<?>) context.getWrapped().getParameter
                (HTTP_SERVLET_REQUEST)).getWrapped();
        if (httpServletRequest instanceof HttpServletRequestWrapper) {
            HttpServletRequestWrapper authenticationFrameworkWrapper = (HttpServletRequestWrapper) httpServletRequest;
            return authenticationFrameworkWrapper.getRemoteAddr();
        }
        return null;
    }

    public static boolean isLoggingEnabled(Map<String, Object> passedCustomParams) {

        boolean isLoggingEnabled = false;
        if (passedCustomParams != null) {
            isLoggingEnabled = passedCustomParams.containsKey(Constants.LOGGING_ENABLED) &&
                    (Boolean) passedCustomParams.get(Constants.LOGGING_ENABLED);
            passedCustomParams.remove(Constants.LOGGING_ENABLED);
        }
        return isLoggingEnabled;
    }

    private static String generateSessionHash(JsAuthenticationContext context) throws FrameworkException {

        if (context.getWrapped().getContextIdentifier() == null) {
            throw new FrameworkException("Context identifier is null.");
        }
        return DigestUtils.sha256Hex(context.getWrapped().getContextIdentifier());
    }
}
