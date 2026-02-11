package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * Main, default implementation of {@link ClientConfigurationProvider}, 
 * the high-level entry point for retrieving {@link IClientConfiguration} instances. 
 * This class wraps a chosen {@link AuthenticationProvider} implementation 
 * and manages additional cross-cutting features as security sessions and applies user's preferences.
 * This class is thread safe: its internal state is not mutable and all collaborators are thread safe.  
 * 
 * @author K. Benedyczak
 */
public class ClientConfigurationProviderImpl implements ClientConfigurationProvider
{
	private Map<String, String[]> securityPreferences;
	private AuthenticationProvider authnProvider;
	private IClientConfiguration basicConfiguration;
	private IClientConfiguration anonymousConfiguration;
	private SecuritySessionPersistence sessionsPersistence;

	/**
	 * 
	 * @param authnProvider object used to actually configure local credential and trust settings.
	 * @param sessionsPersistence used to persist sessions information (or not to persist ;-))
	 * @param securityPreferences map with user's preferences to be applied to the configuration.
	 * @throws Exception
	 */
	public ClientConfigurationProviderImpl(AuthenticationProvider authnProvider, 
			SecuritySessionPersistence sessionsPersistence,
			Map<String, String[]> securityPreferences) throws Exception
	{
		this.securityPreferences = securityPreferences;
		this.authnProvider = authnProvider;
		this.sessionsPersistence = sessionsPersistence;
		basicConfiguration = authnProvider.getBaseClientConfiguration();
		anonymousConfiguration = authnProvider.getAnonymousClientConfiguration();
		sessionsPersistence.readSessionIDs(basicConfiguration.getSessionIDProvider());
	}
	
	/**
	 * For subclasses which need to set up the object step-by-step.
	 */
	protected ClientConfigurationProviderImpl() {}
	
	@Override
	public IClientConfiguration getClientConfiguration(String serviceUrl) throws Exception
	{
		DefaultClientConfiguration securityProperties = authnProvider.getClientConfiguration(serviceUrl);
		//preferences
		Map<String, String[]> target = securityProperties.getRequestedUserAttributes();
		target.putAll(securityPreferences);
		//make sure we use the same session id provider everywhere
		securityProperties.setSessionIDProvider(basicConfiguration.getSessionIDProvider());
		return securityProperties;
	}
	
	@Override
	public void flushSessions() throws IOException
	{
		sessionsPersistence.storeSessionIDs(basicConfiguration.getSessionIDProvider());
	}

	@Override
	public IClientConfiguration getAnonymousClientConfiguration() throws Exception
	{
		return anonymousConfiguration.clone();
	}
	
	@Override
	public IClientConfiguration getBasicClientConfiguration()
	{
		return basicConfiguration.clone();
	}
	
	protected void setSecurityPreferences(Map<String, String[]> securityPreferences)
	{
		this.securityPreferences = new HashMap<>(securityPreferences);
	}

	protected void setAuthnProvider(AuthenticationProvider authnProvider)
	{
		this.authnProvider = authnProvider;
	}

	protected void setBasicConfiguration(IClientConfiguration basicConfiguration)
	{
		this.basicConfiguration = basicConfiguration;
	}
	
	protected void setAnonymousConfiguration(IClientConfiguration anonymousConfiguration)
	{
		this.anonymousConfiguration = anonymousConfiguration;
	}
	
	protected void setSessionsPersistence(SecuritySessionPersistence sessionsPersistence)
	{
		this.sessionsPersistence = sessionsPersistence;
	}

	@Override
	public Map<String, String[]> getSecurityPreferences()
	{
		return new HashMap<String, String[]>(securityPreferences);
	}

	@Override
	public AuthenticationProvider getAuthnProvider()
	{
		return authnProvider;
	}

	@Override
	public SecuritySessionPersistence getSessionsPersistence()
	{
		return sessionsPersistence;
	}

}
