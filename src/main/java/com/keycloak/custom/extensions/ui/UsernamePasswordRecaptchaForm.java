package com.keycloak.custom.extensions.ui;

import java.util.LinkedList;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.credential.CredentialInput;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import com.keycloak.custom.extensions.misc.UsernamePasswordRecaptchaConstants;
import com.keycloak.custom.extensions.misc.UsernamePasswordRecaptchaUtils;

public class UsernamePasswordRecaptchaForm extends AbstractUsernameFormAuthenticator implements Authenticator {
	
    @Override
    public void action(AuthenticationFlowContext context) {    	
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }
        context.success();
    }
    
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }
    
    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
    	String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = invalidUser(context);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }

        // remove leading and trailing whitespace
        username = username.trim();

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }

            return false;
        }
        
        UsernamePasswordRecaptchaUtils.incrementSessionLoginAttempts(context);
        
        displayRecaptcha(context, user);
        
    	if (!UsernamePasswordRecaptchaUtils.checkRecaptcha(context, user, inputData)) {
    		return false;
    	}
        
        if (invalidUser(context, user)) {
            return false;
        }
        
        if (!enabledUser(context, user)) {
    		return false;
    	}
        
        if (!validatePassword(context, user, inputData)) {
            return false;
        }
        
        context.getAuthenticationSession().removeAuthNote(UsernamePasswordRecaptchaConstants.SESSION_LOGIN_ATTEMPTS);;
        
        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }
        context.setUser(user);
        return true;
    }
    
    public void displayRecaptcha(AuthenticationFlowContext context, UserModel user) {
    	if(UsernamePasswordRecaptchaUtils.showLoginRecaptcha(context, user)) {
	    	LoginFormsProvider forms = context.form();
	    	AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
	        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
	        
	        if (captchaConfig == null || captchaConfig.getConfig() == null
	                || captchaConfig.getConfig().get(UsernamePasswordRecaptchaConstants.SITE_KEY) == null
	                || captchaConfig.getConfig().get(UsernamePasswordRecaptchaConstants.SITE_SECRET) == null) {
	            forms.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
	        }
	        
	        String siteKey = captchaConfig.getConfig().get(UsernamePasswordRecaptchaConstants.SITE_KEY);
	        forms.setAttribute("loginRecaptchaRequired", true);
	        forms.setAttribute("recaptchaSiteKey", siteKey);
	        forms.addScript("https://www.google.com/recaptcha/api.js?hl=" + userLanguageTag);
    	}
    }
    
    @Override
    public boolean enabledUser(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            Response challengeResponse = disabledUser(context);
            context.forceChallenge(challengeResponse);
            return false;
        } 
        if (isTemporarilyDisabledByBruteForce(context, user)) {
        	return false;
        }
        return true;
    }
    
    @Override
    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        List<CredentialInput> credentials = new LinkedList<CredentialInput>();
        String password = inputData.getFirst(CredentialRepresentation.PASSWORD);
        credentials.add(UserCredentialModel.password(password));

        if (isTemporarilyDisabledByBruteForce(context, user)) {
        	return false;
        }
        
        if (password != null && !password.isEmpty() && context.getSession().userCredentialManager().isValid(context.getRealm(), user, credentials)) {
            return true;
        } else {
        	// display account locked message if account is expected to be locked on next failure challenge
            if (context.getRealm().isBruteForceProtected()) {
        		UserLoginFailureModel userFailure = context.getSession().sessions().getUserLoginFailure(context.getRealm(), user.getId());
            	if (userFailure != null && userFailure.getNumFailures() + 1 == context.getRealm().getFailureFactor()) {
            		context.getEvent().user(user);
            		context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            		Response challengeResponse = disabledUser(context);
            		context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            		context.clearUser();
            		return false;
            	}
        	}
        	
            context.getEvent().user(user);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = invalidCredentials(context);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            context.clearUser();
            return false;
        }
    }
    
    private boolean isTemporarilyDisabledByBruteForce(AuthenticationFlowContext context, UserModel user) {
        if (context.getRealm().isBruteForceProtected()) {
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                context.getEvent().user(user);
                context.getEvent().error(Errors.USER_TEMPORARILY_DISABLED);
                Response challengeResponse = disabledUser(context);
                context.forceChallenge(challengeResponse);
                return true;
            }
        }
        return false;
    }

    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<String, String>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
            } else {
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("rememberMe", "on");
            }
        }
        
        displayRecaptcha(context, null);
        
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);
        
        return forms.createLogin();
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }
}
