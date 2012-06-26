package eu.unicore.security.xfireutil.client;

import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * allows to configure a handler with security properties
 * 
 * @author schuller
 */
public interface Configurable {

	/**
	 * configure using the given client properties
	 * @param properties - {@link IClientConfiguration}
	 */
	public void configure(IClientConfiguration properties);
	
}
