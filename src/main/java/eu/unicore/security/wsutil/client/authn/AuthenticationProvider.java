package eu.unicore.security.wsutil.client.authn;

import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * This interface encapsulates the various ways that a user can "log in" to UNICORE<br/>
 * Implementations shouldn't be used directly, only via {@link ClientConfigurationProvider}.
 * <p>
 * Implementations must be thread safe
 * @author schuller
 * @author golbi
 */
public interface AuthenticationProvider {

	/**
	 * returns the name of the AuthN mechanism.
	 */
	public String getName();
	
	/**
	 * Returns a description of the AuthN mechanism
	 */
	public String getDescription();
	
	/**
	 * return human-readable usage info (e.g. config properties and their description)
	 */
	public String getUsage();
	
	/**
	 * The main method of this interface is used to retrieve a working 
	 * {@link IClientConfiguration}. As the returned implementation sometimes needs to be modified,
	 * the mutable {@link DefaultClientConfiguration} or its extension is required. 
	 * @param targetAddress address of the service for which the returned settings will be used
	 */
	public DefaultClientConfiguration getClientConfiguration(String targetAddress) throws Exception;

	/**
	 * Gives an access to a possibly anonymous client. The client will have its trust settings configured 
	 * (in the way the general client's configuration sets them up - so if the SSL is disabled 
	 * then the trust settings are null), but the credential and delegation won't be set up.
	 * @throws Exception
	 */
	public IClientConfiguration getAnonymousClientConfiguration() throws Exception;

	/**
	 * The helper method of this interface is used to retrieve a partially working 
	 * {@link IClientConfiguration}. The returned implementation won't have authN and trust set up,
	 * but all other client settings should be properly set up. The intention is to have 
	 * a basic configuration object available without contacting external services. 
	 */
	public DefaultClientConfiguration getBaseClientConfiguration() throws Exception;
}
