/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * Main, default implementation of {@link ClientConfigurationProvider}, 
 * the high-level entry point for retrieving {@link IClientConfiguration} instances. 
 * This class wraps a chosen {@link AuthenticationProvider} implementation 
 * and manages additional cross-cutting features as security sessions and applies user's preferences.
 * <p>
 * The key to use this class is to provide proper collaborators, from which the {@link AuthenticationProvider} is
 * the most important. You can develop your own or use one of the available ones: {@link KeystoreAuthN} or
 * {@link SAMLAuthN}. Those two are configured with {@link Properties} and allow to use the two standard authentication 
 * mechanisms available in UNICORE 7.
 * <p> 
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
	private ServiceIdentityResolver identityResolver;
	
	/**
	 * 
	 * @param authnProvider object used to actually configure local credential and trust settings.
	 * @param sessionsPersistence used to persist sessions information (or not to persist ;-))
	 * @param identityResolver used to discover identity of a service for which a DN was not explicitly given
	 * @param securityPreferences map with user's preferences to be applied to the configuration.
	 * @throws Exception
	 */
	public ClientConfigurationProviderImpl(AuthenticationProvider authnProvider, 
			SecuritySessionPersistence sessionsPersistence, ServiceIdentityResolver identityResolver,
			Map<String, String[]> securityPreferences) throws Exception
	{
		this.securityPreferences = securityPreferences;
		this.authnProvider = authnProvider;
		this.sessionsPersistence = sessionsPersistence;
		this.identityResolver = identityResolver;
		basicConfiguration = authnProvider.getBaseClientConfiguration();
		anonymousConfiguration = authnProvider.getAnonymousClientConfiguration();
		sessionsPersistence.readSessionIDs(basicConfiguration.getSessionIDProvider());
	}
	
	/**
	 * For subclasses which need to set up the object step-by-step.
	 */
	protected ClientConfigurationProviderImpl() {}
	
	@Override
	public IClientConfiguration getClientConfiguration(String serviceUrl, String serviceIdentity, 
			DelegationSpecification delegate) throws Exception
	{
		if (serviceUrl == null)
			throw new IllegalArgumentException("Service URL must be always given");
		if (serviceUrl.startsWith("http://")) //insecure, likely tests, no security
			return getAnonymousClientConfiguration();
		
		if (serviceIdentity == null)
		{
			try
			{
				serviceIdentity = identityResolver.resolveIdentity(serviceUrl);
			} catch (IOException e)
			{
				if (delegate.isRequired())
					throw e;
				//if no delegation we can try to continue, it depends on authnProvider
				//whether it can work without the target DN.
			}
		} else
			identityResolver.registerIdentity(serviceUrl, serviceIdentity);
		//authn,trust and ETD
		DefaultClientConfiguration securityProperties = authnProvider.getClientConfiguration(serviceUrl,
				serviceIdentity, delegate);
		
		//preferences
		Map<String, String[]> target = securityProperties.getETDSettings().getRequestedUserAttributes2();
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
		this.securityPreferences = new HashMap<String, String[]>(securityPreferences);
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
	public ServiceIdentityResolver getIdentityResolver()
	{
		return identityResolver;
	}

	protected void setIdentityResolver(ServiceIdentityResolver identityResolver)
	{
		this.identityResolver = identityResolver;
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
