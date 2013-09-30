/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.Map.Entry;

import javax.security.auth.x500.X500Principal;

import com.sun.xml.txw2.IllegalSignatureException;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.security.canl.LoggingStoreUpdateListener;
import eu.unicore.security.canl.PasswordCallback;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.util.configuration.PropertyMD;
import eu.unicore.util.httpclient.ClientProperties;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.ETDClientSettings;

/**
 * Code useful for various {@link AuthenticationProvider} implementations which are configured with Java Properties.
 * @author K. Benedyczak
 */
public abstract class PropertiesBasedAuthenticationProvider implements AuthenticationProvider
{
	protected Properties properties;
	protected PasswordCallback truststorePasswordCallback;

	public PropertiesBasedAuthenticationProvider(Properties properties,
			PasswordCallback truststorePasswordCallback)
	{
		this.properties = properties;
		this.truststorePasswordCallback = truststorePasswordCallback;
	}

	protected PropertiesBasedAuthenticationProvider()
	{
	}

	/**
	 * Returns client configuration with anonymous local client. I.e. all HTTP client properties and trust settings
	 * are loaded, credential settings are ignored. Trust settings are loaded only when SSL is enabled for the client.
	 * @param uccPreferences
	 * @return
	 */
	@Override
	public DefaultClientConfiguration getAnonymousClientConfiguration()
	{
		String sslEnabled = properties.getProperty(ClientProperties.DEFAULT_PREFIX + ClientProperties.PROP_SSL_ENABLED);
		X509CertChainValidatorExt validator = null;
		if (sslEnabled == null || "true".equalsIgnoreCase(sslEnabled))
		{
			TruststoreProperties trustProperties = new TruststoreProperties(properties, 
					Collections.singleton(new LoggingStoreUpdateListener()), truststorePasswordCallback);
			validator = trustProperties.getValidator();
		}
		DefaultAuthnAndTrustConfiguration authAndTrust = new DefaultAuthnAndTrustConfiguration(validator, null);
		Properties copy = new Properties();
		copy.putAll(properties);
		copy.setProperty(ClientProperties.DEFAULT_PREFIX+
				ClientProperties.PROP_SSL_AUTHN_ENABLED, "false");
		copy.setProperty(ClientProperties.DEFAULT_PREFIX+
				ClientProperties.PROP_MESSAGE_SIGNING_ENABLED, "false");

		return new ClientProperties(copy, authAndTrust);
	}

	/**
	 * Returns a client configuration which reflects what is set in the user configuration.
	 * This configuration is not Authenticator specific in any way, and therefore both local credential 
	 * and validator are not set (credential is null, validator is trust-all).
	 * Additionally SSL authn and message signing is turned off, regardless of properties file settings.
	 * 
	 * 
	 * @return
	 */
	public DefaultClientConfiguration getBaseClientConfiguration()
	{
		X509CertChainValidatorExt validator = new BinaryCertChainValidator(true);
		DefaultAuthnAndTrustConfiguration authAndTrust = new DefaultAuthnAndTrustConfiguration(validator, null);
		Properties copy = new Properties();
		copy.putAll(properties);
		copy.setProperty(ClientProperties.DEFAULT_PREFIX+
				ClientProperties.PROP_SSL_AUTHN_ENABLED, "false");
		copy.setProperty(ClientProperties.DEFAULT_PREFIX+
				ClientProperties.PROP_MESSAGE_SIGNING_ENABLED, "false");

		return new ClientProperties(copy, authAndTrust);
	}

	//workaround: use reflection to access possibly private Meta field
	@SuppressWarnings("unchecked")
	protected Map<String,PropertyMD>getMeta(Class<?> props){
		try{
			Field f=props.getDeclaredField("META");
			f.setAccessible(true);
			return(Map<String,PropertyMD>)f.get(null);
		}catch(Exception ex){
			throw new IllegalStateException(ex);
		}
	}


	protected String getMeta(Class<?> clazz, String prefix)
	{
		StringBuilder ret = new StringBuilder();
		for(Entry<String, PropertyMD> entry: getMeta(clazz).entrySet()){
			PropertyMD prop=entry.getValue();
			if(!prop.isHidden()){
				ret.append(prefix+entry.getKey()+" : "+prop.getDescription());
			}
		}
		return ret.toString();
	}

	protected void applyLocalDelegation(DefaultClientConfiguration sp, String targetDn, 
			DelegationSpecification delegate)
	{
		if (delegate.isDelegate())
		{
			if (targetDn == null){
				if(delegate.isRequired())
					throw new IllegalSignatureException("When delegation is used the " +
						"target service DN must be given.");
			}
			else{
				ETDClientSettings etdSettings = sp.getETDSettings();
				etdSettings.setExtendTrustDelegation(true);
				etdSettings.setReceiver(new X500Principal(targetDn));
				etdSettings.setDelegationRestrictions(delegate.getRestrictions());
			}
		}
	}
}
