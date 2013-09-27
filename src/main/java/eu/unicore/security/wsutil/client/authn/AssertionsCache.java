/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import eu.unicore.security.wsutil.samlclient.AuthnResponseAssertions;

/**
 * Implementations provide cache of assertions. The cache may be persistent or not. Must be thread safe.
 * @author K. Benedyczak
 */
public interface AssertionsCache
{
	/**
	 * @param key
	 * @return cached assertions or null if not found
	 */
	public AuthnResponseAssertions get(String key);
	
	/**
	 * Store the assertions under the given key
	 * @param key
	 * @param value
	 */
	public void store(String key, AuthnResponseAssertions value);
}
