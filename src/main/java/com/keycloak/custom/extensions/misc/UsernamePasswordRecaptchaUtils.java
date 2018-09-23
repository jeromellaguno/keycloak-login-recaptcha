package com.keycloak.custom.extensions.misc;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

public class UsernamePasswordRecaptchaUtils {
    
    public static boolean showLoginRecaptcha(AuthenticationFlowContext context, UserModel user) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        int recaptchaLoginAttemptsConfig = Integer.parseInt(captchaConfig.getConfig().get(UsernamePasswordRecaptchaConstants.RECAPTCHA_LOGIN_ATTEMPTS));
    	
        if(recaptchaLoginAttemptsConfig == 0) {
        	return true;
        }
        
        int loginAttempts = getLoginAttempts(context, user);
        return loginAttempts >= recaptchaLoginAttemptsConfig;
    }
    
    public static boolean checkRecaptcha(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> formData) {
    	AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        int recaptchaLoginAttemptsConfig = Integer.parseInt(captchaConfig.getConfig().get(UsernamePasswordRecaptchaConstants.RECAPTCHA_LOGIN_ATTEMPTS));
    	
        int sessionLoginAttempts = getSessionLoginAttempts(context);
        int loginAttempts = getLoginAttempts(context, user);
        
    	if (sessionLoginAttempts > 1 && loginAttempts > recaptchaLoginAttemptsConfig) {
    		List<FormMessage> errors = new ArrayList<FormMessage>();
    		boolean success = false;
    		
    		String captcha = formData.getFirst(UsernamePasswordRecaptchaConstants.G_RECAPTCHA_RESPONSE);
	        if (!Validation.isBlank(captcha)) {
	            String secret = captchaConfig.getConfig().get(UsernamePasswordRecaptchaConstants.SITE_SECRET);
	            
	            success = validateRecaptcha(context, success, captcha, secret);
	        }
	        if (!success) {
	            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
	            formData.remove(UsernamePasswordRecaptchaConstants.G_RECAPTCHA_RESPONSE);
	            context.getEvent().error(Messages.RECAPTCHA_FAILED);
	            Response challengeResponse = context.form().setError(Messages.RECAPTCHA_FAILED).createLogin();
	            context.forceChallenge(challengeResponse);
	            return false;
	        }
    	}
    	
    	return true;
    }
    
    public static int getLoginAttempts(AuthenticationFlowContext context, UserModel user) {
    	int loginAttempts = getSessionLoginAttempts(context);
    	if (user != null) {
    		UserLoginFailureModel userFailure = context.getSession().sessions().getUserLoginFailure(context.getRealm(), user.getId());
    		if (userFailure != null && userFailure.getNumFailures() > loginAttempts) {
    			loginAttempts = userFailure.getNumFailures();
    		}
    	}
    	return loginAttempts;
    }
    
    public static int getSessionLoginAttempts(AuthenticationFlowContext context) {
    	String sessionLoginAttempts = context.getAuthenticationSession().getAuthNote(UsernamePasswordRecaptchaConstants.SESSION_LOGIN_ATTEMPTS);
    	return sessionLoginAttempts != null ? Integer.parseInt(sessionLoginAttempts) : 0;
    }
    
    public static void incrementSessionLoginAttempts(AuthenticationFlowContext context) {
    	Integer loginAttempts = UsernamePasswordRecaptchaUtils.getSessionLoginAttempts(context);
    	loginAttempts += 1;
    	context.getAuthenticationSession().setAuthNote(UsernamePasswordRecaptchaConstants.SESSION_LOGIN_ATTEMPTS, loginAttempts.toString());
    }
    
    protected static boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://www.google.com/recaptcha/api/siteverify");
        List<NameValuePair> formparams = new LinkedList<NameValuePair>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                Object val = json.get("success");
                success = Boolean.TRUE.equals(val);
            } finally {
                content.close();
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }
	
}
