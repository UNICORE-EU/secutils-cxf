/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;

/**
 * Implementations are used to resolve identity (DN) of a given service or more concretely
 * a DN of a container which is hosting the service.
 * @author K. Benedyczak
 */
public interface ServiceIdentityResolver
{
	/**
	 * @param serviceURL
	 * @return DN of the service, never null
	 * @throws IOException if resolve is not possible
	 */
	public String resolveIdentity(String serviceURL) throws IOException;
	
	/**
	 * If the outside code establishes an identity of a service in any way, this identity can be stored in
	 * the resolver for future use.
	 * @param serviceURL
	 * @param identity
	 */
	public void registerIdentity(String serviceURL, String identity);
}
