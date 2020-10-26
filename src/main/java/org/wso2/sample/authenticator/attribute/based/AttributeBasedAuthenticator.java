/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.authenticator.attribute.based;

import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.sample.authenticator.attribute.based.internal.AttributeBasedAuthenticatorServiceComponent;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.HashMap;

public class AttributeBasedAuthenticator extends BasicAuthenticator {

    private static final Log log = LogFactory.getLog(AttributeBasedAuthenticator.class);

    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";

    private String authenticatingClaimUri;

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {


        boolean isAuthenticated;
        UserStoreManager userStoreManager;
        String internalUsername;

        authenticatingClaimUri = getAuthenticatorConfig().getParameterMap().get(
                AttributeBasedAuthenticatorConstants.AUTHENTICATOR_PROPERTY_AUTHENTICATING_USERNAME_CLAIM);

        if (authenticatingClaimUri == null) {
            authenticatingClaimUri = AttributeBasedAuthenticatorConstants.DEFAULT_AUTHENTICATING_USERNAME_CLAIM;
        }

        String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<String, Object>();
            context.setProperties(authProperties);
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        // Reset RE_CAPTCHA_USER_DOMAIN thread local variable before the authentication
        IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = AttributeBasedAuthenticatorServiceComponent.getRealmService().
                    getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();

                internalUsername = getUsernameFromClaim(username, userStoreManager);
                isAuthenticated = userStoreManager.
                        authenticate(MultitenantUtils.getTenantAwareUsername(internalUsername), password);
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                internalUsername = IdentityUtil.addDomainToName(internalUsername, IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN)
                        .toString());
            }
            IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(internalUsername));
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(internalUsername);
        authProperties.put("user-tenant-domain", tenantDomain);

        internalUsername = FrameworkUtils.prependUserStoreDomainToName(internalUsername);

        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(internalUsername));

        String rememberMe = request.getParameter("chkRemember");
        if ("on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
    }

    private String getUsernameFromClaim(String claimValue, UserStoreManager userStoreManager)
            throws UserStoreException, AuthenticationFailedException {

        String[] userList;
        String tenantDomain = MultitenantUtils.getTenantDomain(claimValue);
        String tenantAwareClaim = MultitenantUtils.getTenantAwareUsername(claimValue);

        if (log.isDebugEnabled()) {
            log.info("Searching for a user with " + authenticatingClaimUri + ": " + tenantAwareClaim + " and tenant domain: " + tenantDomain);
        }
        userList = userStoreManager.getUserList(authenticatingClaimUri, tenantAwareClaim,
                AttributeBasedAuthenticatorConstants.DEFAULT_PROFILE);

        if (userList == null || userList.length == 0) {
            String errorMessage = "No user found with the provided " + authenticatingClaimUri + ": " + claimValue;
            log.error(errorMessage);

            if (isAuthPolicyAccountExistCheck()) {
                IdentityErrorMsgContext identityErrorMsgContext = new IdentityErrorMsgContext(UserCoreConstants
                        .ErrorCode.USER_DOES_NOT_EXIST);
                IdentityUtil.setIdentityErrorMsg(identityErrorMsgContext);
            }

            throw new AuthenticationFailedException(errorMessage);
        } else if (userList.length == 1) {
            if (log.isDebugEnabled()) {
                log.debug("Found single user " + userList[0] + " with the " + authenticatingClaimUri + ": " + claimValue);
            }
            return userList[0] + "@" + tenantDomain;
        }

        String errorMessage = "Multiple users exist with the same email address " + claimValue + ". " + userList.toString();
        log.error(errorMessage);
        throw new AuthenticationFailedException(errorMessage);
    }

    private boolean isAuthPolicyAccountExistCheck() {

        return Boolean.parseBoolean(IdentityUtil.getProperty("AuthenticationPolicy.CheckAccountExist"));
    }

    @Override
    public String getFriendlyName() {
        return AttributeBasedAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return AttributeBasedAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

}
