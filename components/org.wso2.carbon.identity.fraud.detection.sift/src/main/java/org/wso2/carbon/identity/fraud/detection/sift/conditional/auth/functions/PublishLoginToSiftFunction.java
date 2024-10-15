package org.wso2.carbon.identity.fraud.detection.sift.conditional.auth.functions;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

import java.util.List;

/**
 * Functional interface to publish login event to Sift.
 */
@FunctionalInterface
public interface PublishLoginToSiftFunction {

    /**
     * Publish login event information to Sift.
     *
     * @param context     Authentication context.
     * @param loginStatus Login status. Expected values are "LOGIN_SUCCESS", "LOGIN_FAILED" and "PRE_LOGIN".
     * @param paramKeys   Parameter keys which is used to get the data to be sent to Sift.
     * @param paramMap    [Optional] An arbitrary data map to be sent to Sift. A json object can be passed to the
     * @throws FrameworkException FrameworkException.
     */
    void publishLoginEventInfoToSift(JsAuthenticationContext context, String loginStatus, List<String> paramKeys,
                                        Object... paramMap) throws FrameworkException;
}
