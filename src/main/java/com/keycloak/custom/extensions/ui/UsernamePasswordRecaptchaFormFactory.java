package com.keycloak.custom.extensions.ui;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import com.keycloak.custom.extensions.misc.UsernamePasswordRecaptchaConstants;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:jeromellaguno@yahoo.com">Jerome Llaguno</a>
 * @since 09/22/2018
 */
public class UsernamePasswordRecaptchaFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "username-password-recaptcha-form";
    public static final UsernamePasswordRecaptchaForm SINGLETON = new UsernamePasswordRecaptchaForm();

    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }
    
    public void init(Config.Scope config) {

    }
    
    public void postInit(KeycloakSessionFactory factory) {

    }
    
    public void close() {

    }
    
    public String getId() {
        return PROVIDER_ID;
    }
    
    public String getReferenceCategory() {
        return UserCredentialModel.PASSWORD;
    }
    
    public boolean isConfigurable() {
        return true;
    }
    
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };
    
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    
    public String getDisplayType() {
        return "Username Password Form with Recaptcha";
    }
    
    public String getHelpText() {
        return "Validates a username and password from login form. If the number of login attempts has met, will show a recaptcha.";
    }
    
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(UsernamePasswordRecaptchaConstants.SITE_KEY);
        property.setLabel("Recaptcha Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google Recaptcha Site Key");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(UsernamePasswordRecaptchaConstants.SITE_SECRET);
        property.setLabel("Recaptcha Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google Recaptcha Secret");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(UsernamePasswordRecaptchaConstants.RECAPTCHA_LOGIN_ATTEMPTS);
        property.setLabel("Recaptcha login attempts");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Number of Login Attempts before showing recaptcha");
        CONFIG_PROPERTIES.add(property);

    }
        
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

}
