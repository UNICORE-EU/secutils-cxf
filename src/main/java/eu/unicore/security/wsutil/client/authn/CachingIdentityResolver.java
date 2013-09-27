/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple {@link ServiceIdentityResolver} which is simply caching the previously resolved identities.
 * <p>
 * This class is thread safe.
 * 
 * @author K. Benedyczak
 */
public class CachingIdentityResolver implements ServiceIdentityResolver
{
	protected Map<String, String> cachedIdentities = new HashMap<String, String>(10);
	
	@Override
	public synchronized String resolveIdentity(String serviceURL) throws IOException
	{
		String containerAddr = getContainerAddress(serviceURL);
		String ret = cachedIdentities.get(containerAddr);
		if (ret == null)
			throw new IOException("Identity not known");
		return ret;
	}

	@Override
	public void registerIdentity(String serviceURL, String identity)
	{
		String containerAddr = getContainerAddress(serviceURL);
		cachedIdentities.put(containerAddr, identity);
	}
	
	protected String getContainerAddress(String serviceURL)
	{
		int end = serviceURL.indexOf("/services");
		if (end != -1)
			return serviceURL.substring(0, end);
		return serviceURL;
	}
}
