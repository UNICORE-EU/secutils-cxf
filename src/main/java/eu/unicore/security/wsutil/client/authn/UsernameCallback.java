/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

/**
 * Implementations should provide username.
 * 
 * @author K. Benedyczak
 */
public interface UsernameCallback
{
	public String getUsername();
}
