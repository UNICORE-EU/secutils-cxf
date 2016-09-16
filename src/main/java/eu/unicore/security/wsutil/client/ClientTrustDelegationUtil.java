/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.client;

import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;

import eu.unicore.security.etd.TrustDelegation;


/**
 * This class provides static methods to configure trust delegation handler 
 * ({@link TDOutHandler} for the CXF proxy. Note that is also adds User statements,
 * not only trust delegation statements. 
 * @author K. Benedyczak
 */
public class ClientTrustDelegationUtil
{
	/**
	 * Configures trust delegation for the CXF proxy. It is assumed that standard
	 * CXF was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * The assumption here is that 
	 * the issuer of the first trust delegation in the list is the USER (on her 
	 * behalf request shall be executed) and the subject of the last trust delegation
	 * in chain is a CONSIGNOR (so the guy who actually make the request, or to state
	 * it in another way: you).
	 * 
	 * @param cxfProxy Object used to make WS calls via CXF.
	 * @param tdChain list of trust delegations.
	 */
	public static void addTrustDelegation(Object cxfProxy, 
			List<TrustDelegation> tdChain)
	{
		Client cxfClient = ClientProxy.getClient(cxfProxy);
		addTrustDelegation(cxfClient, tdChain);
	}
	
	/**
	 * Configures trust delegation for the CXF client. This method is for use 
	 * with custom code with manipulates CXF default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * The assumption here is that 
	 * the issuer of the first trust delegation in the list is the USER (on her 
	 * behalf request shall be executed) and the subject of the last trust delegation
	 * in chain is a CONSIGNOR (so the guy who actually make the request, or to state
	 * it in another way: you).
	 * 
	 * @param cxfClient CXF client underlying CXF proxy.
	 * @param tdChain list of trust delegations.
	 */
	public static void addTrustDelegation(Client cxfClient, 
			List<TrustDelegation> tdChain)
	{
		if (tdChain == null || tdChain.size() == 0)
			throw new IllegalArgumentException(
				"Trust delegation chain can't be null/empty");
		
		TrustDelegation td1 = tdChain.get(0);
		TrustDelegation tdLast = tdChain.get(tdChain.size() - 1);
		addTrustDelegation(cxfClient, tdChain, 
				td1.getIssuerFromSignature()[0], tdLast.getSubjectName());
	}
	
	
	/**
	 * Configures trust delegation for the CXF proxy. It is assumed that standard
	 * CXFProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User 
	 * (identified by certificate). 
	 *  
	 * @param cxfProxy Object used to make WS calls via CXF.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Object cxfProxy, 
			List<TrustDelegation> tdChain, X509Certificate user,
			String callerDN)
	{
		Client CXFClient = ClientProxy.getClient(cxfProxy);
		addTrustDelegation(CXFClient, tdChain, user, callerDN);
	}

	/**
	 * Configures trust delegation for the CXF client. This method is for use 
	 * with custom code with manipulates CXF default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and the User
	 * (identified by a certificate). 
	 *  
	 * @param cxfClient CXF client underlying CXF proxy.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Client cxfClient, 
			List<TrustDelegation> tdChain, X509Certificate user,
			String callerDN)
	{
		addTrustDelegation(cxfClient, tdChain, user, null, callerDN);
	}

	/**
	 * Configures trust delegation for the CXF proxy. It is assumed that standard
	 * CXFProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User 
	 * (identified by a DN). 
	 *  
	 * @param cxfProxy Object used to make WS calls via CXF.
	 * @param tdChain list of trust delegations.
	 * @param userDN DN of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Object cxfProxy, 
			List<TrustDelegation> tdChain, String userDN,
			String callerDN)
	{
		Client CXFClient = ClientProxy.getClient(cxfProxy);
		addTrustDelegation(CXFClient, tdChain, null, userDN, callerDN);
	}

	/**
	 * Configures trust delegation for the CXF client. This method is for use 
	 * with custom code with manipulates CXF default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User
	 * (identified by a DN). 
	 *  
	 * @param cxfClient CXF client underlying CXF proxy.
	 * @param tdChain list of trust delegations.
	 * @param userDN DN of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Client cxfClient, 
			List<TrustDelegation> tdChain, String userDN,
			String callerDN)
	{
		addTrustDelegation(cxfClient, tdChain, null, userDN, callerDN);
	}
	
	/**
	 * Configures trust delegation for the CXF client. This method is for use 
	 * with custom code with manipulates CXF default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User. 
	 *  
	 * @param cxfClient CXF client underlying CXF proxy.
	 * @param tdChain list of trust delegations.
	 * @param userDN DN of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	private static void addTrustDelegation(Client cxfClient, 
			List<TrustDelegation> tdChain, X509Certificate user, String userDN,
			String callerDN)
	{
		List<?> outHandlers = cxfClient.getOutInterceptors();
		TDOutHandler tdHandler = null;
		for (Object h: outHandlers)
			if (h instanceof TDOutHandler)
			{
				tdHandler = (TDOutHandler)h;
				break;
			}
		if (tdHandler != null)
			outHandlers.remove(tdHandler);
		if (userDN == null)
			tdHandler = new TDOutHandler(tdChain, user, callerDN);
		else
			tdHandler = new TDOutHandler(tdChain, userDN, callerDN);
		cxfClient.getOutInterceptors().add(tdHandler);
	}

	/**
	 * Removes all trust delegation handlers from the given proxy.
	 * <p>
	 * It is assumed that standard CXFProxy was used (so don't use this 
	 * method clients obtained with WSRFLite or other higher level frameworks
	 *  -- see other method).
	 * @param cxfProxy Object used to make WS calls via CXF.
	 */
	public static void removeTrustDelegation(Object cxfProxy)
	{
		Client CXFClient = ClientProxy.getClient(cxfProxy);
		removeTrustDelegation(CXFClient);
	}
	
	/**
	 * Removes all trust delegation handlers from the given proxy.
	 * <p>
	 * @param cxfClient CXF client underlying CXF proxy.
	 */
	public static void removeTrustDelegation(Client cxfClient)
	{
		List<?> outHandlers = cxfClient.getOutInterceptors();
		for (int i=outHandlers.size()-1; i>=0; i--)
		{
			Object h = outHandlers.get(i);
			if (h instanceof TDOutHandler)
				outHandlers.remove(i);
		}
	}
}





