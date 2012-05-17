/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2008-12-22
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil.client;

import java.util.Set;

import org.codehaus.xfire.MessageContext;
import org.codehaus.xfire.addressing.AddressingOperationInfo;
import org.codehaus.xfire.client.Client;
import org.codehaus.xfire.service.OperationInfo;
import org.codehaus.xfire.soap.AbstractSoapBinding;

import eu.unicore.security.xfireutil.DSigDecider;

/**
 * Simple implementation of {@link DSigDecider} for client calls. 
 * It decides basing on information which is retrieved from {@link MessageContext}.
 * Additionally one may set SIGN_MESSAGE context property to true to turn on digital 
 * signature for the call. 
 * 
 * @see XFireClientFactory
 * @author golbi
 */
public class ContextDSigDecider implements DSigDecider
{
	public final static String SIGN_MESSAGE = ContextDSigDecider.class.getName() + "doSign";
	public final static String SIGNED_OPERATIONS = ContextDSigDecider.class.getName() + "signedOperations";
	
	public boolean isMessageDSigCandidate(MessageContext ctx)
	{
		if(Boolean.TRUE.equals(ctx.getProperty(Client.CLIENT_MODE)))
			return clientCall(ctx);
		return false;
	}

	private boolean clientCall(MessageContext ctx)
	{
		//manually set (e.g. for non-WSA call)?
		if (Boolean.TRUE.equals(ctx.getProperty(SIGN_MESSAGE)))
			return true;
		Client client = ctx.getClient();
		@SuppressWarnings("unchecked")
		Set<String> signedOperations = (Set<String>) client.getProperty(SIGNED_OPERATIONS);
		if (signedOperations == null)
			return false;
		//check if this request was signed, decided by SOAP /WSA action
		OperationInfo oi = ctx.getExchange().getOperation();
		AddressingOperationInfo aoi = (AddressingOperationInfo)oi.getProperty(
			AddressingOperationInfo.ADDRESSING_OPERATION_KEY);
		if(aoi == null)
		{
			//no addressing, so we are talking to a plain ws
			if (ctx.getBinding() instanceof AbstractSoapBinding)
			{
				String action = ((AbstractSoapBinding)ctx.getBinding()).getSoapAction(oi);
				if (action == null)
					return false;
				return signedOperations.contains(action);
			}
			return false;
		}
		String action = aoi.getInAction();
		if (action==null)
			return false;
		return signedOperations.contains(action);
	}
}








