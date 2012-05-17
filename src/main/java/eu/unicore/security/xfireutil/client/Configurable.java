package eu.unicore.security.xfireutil.client;

import eu.unicore.security.util.client.IClientConfiguration;

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
