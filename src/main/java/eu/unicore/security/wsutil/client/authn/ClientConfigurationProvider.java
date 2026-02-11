package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;
import java.util.Map;

import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * Main, high-level entry point for retrieving {@link IClientConfiguration} instances. 
 * Implementation will wrap a chosen {@link AuthenticationProvider} implementation 
 * and manage additional cross-cutting features as security sessions and applies user's preferences.
 * @author K. Benedyczak
 */
public interface ClientConfigurationProvider
{
	/**
	 * The main method
	 * @param serviceUrl target service url. Must be given always.
	 */
	public IClientConfiguration getClientConfiguration(String serviceUrl) throws Exception;

	/**
	 * Dumps current sessions state to disk
	 * @throws IOException 
	 */
	public void flushSessions() throws IOException;

	/**
	 * Gives an access to a possibly anonymous client. The client will have its trust settings configured 
	 * (in the way the general client's configuration sets them up - if the SSL is disabled 
	 * then the trust settings are null), but the credential and delegation won't be set up.
	 * @throws Exception
	 */
	public IClientConfiguration getAnonymousClientConfiguration() throws Exception;

	/**
	 * In rare cases this method can be used. The returned object is partially configured - is not useful
	 * for making connections but can be used to retrieve static settings or shared objects.
	 */
	public IClientConfiguration getBasicClientConfiguration();

	public Map<String, String[]> getSecurityPreferences();

	public AuthenticationProvider getAuthnProvider();

	public SecuritySessionPersistence getSessionsPersistence();

}
