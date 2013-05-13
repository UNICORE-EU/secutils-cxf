/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import javax.annotation.Resource;
import javax.jws.WebService;
import javax.security.auth.x500.X500Principal;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;

import eu.unicore.security.HTTPAuthNTokens;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.UserAttributeHandler;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.wsutil.client.ConditionalGetUtil;


/**
 * @author K. Benedyczak
 */
@WebService(endpointInterface="eu.unicore.security.wsutil.SimpleSecurityService")
public class SimpleSecurityServiceImpl implements SimpleSecurityService
{

	public static SecurityTokens lastCallTokens;
	
	@Resource
	private WebServiceContext context;

	private SecurityTokens getTokens()
	{
		MessageContext ctx = context.getMessageContext();
		SecurityTokens tokens = (SecurityTokens)ctx.get(SecurityTokens.KEY);
		lastCallTokens=tokens;
		return tokens;
	}

	public String TestSignature() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		return tokens.getMessageSignatureStatus().name();
	}

	public String TestSignature2() throws RemoteException
	{
		getTokens();
		MessageContext ctx = context.getMessageContext();
		if (ctx.get("tola") != null)
			return "OK";
		return "baad";
	}

	public String TestConsignor() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		X509Certificate cc = tokens.getConsignorCertificate();
		if (cc == null)
			return null;
		return cc.getSubjectX500Principal().getName();
	}
	
	public String TestETDValid() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		return ""+(tokens.isConsignorTrusted()&&tokens.getTrustDelegationTokens().size()>0);
	}


	public String TestETDIssuer() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		List<TrustDelegation> tds = tokens.getTrustDelegationTokens();
		return tds.get(0).getIssuerDN();
	}

	public String TestETDLastSubject() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		List<TrustDelegation> tds = tokens.getTrustDelegationTokens();
		return tds.get(tds.size() - 1).getSubjectDN();
	}

	public String TestHTTPCreds() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		HTTPAuthNTokens a = (HTTPAuthNTokens) tokens.getContext().get(
				SecurityTokens.CTX_LOGIN_HTTP);
		return a.getUserName() + "-" + a.getPasswd();
	}

	public String TestUser() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		X509Certificate cert = tokens.getUserCertificate(); 
		if (cert != null)
			return cert.getSubjectX500Principal().getName();
		else
			return tokens.getUserName().getName();
	}

	public String TestEffectiveUser() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		X500Principal effUser = tokens.getEffectiveUserName(); 
		return effUser == null ? null : effUser.getName();
	}

	@Override
	public String TestPreference() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		String v = (String) tokens.getContext().get("PREF_preference");
		return "preference|"+v;
	}

	@Override
	public String TestAction() throws RemoteException
	{
		//return the action as retrieved from by the AuthIn handler
		return (String)getTokens().getContext().get(SecurityTokens.CTX_SOAP_ACTION);
	}

	@Override
	public String TestIP() throws RemoteException {
		SecurityTokens tokens = getTokens();
		return tokens.getClientIP();
	}

	public static String currentRepresentation="test123";
	public static Calendar lastMod=Calendar.getInstance();

	@Override
	public String TestConditionalGet() throws RemoteException {
		if(ConditionalGetUtil.Server.mustSendData(lastMod, computeEtag())){
			return currentRepresentation;	
		}
		else return "";
	}

	private String computeEtag(){
		return ConditionalGetUtil.Server.md5(currentRepresentation);
	}


	public static class SimpleUserAttributeHandler implements UserAttributeHandler 
	{
		@Override
		public void processUserDefinedAttribute(String name, String nameFormat, 
				XmlObject[]values, SecurityTokens tokens)
		{
			tokens.getContext().put("PREF_" + name, ((XmlString)values[0]).getStringValue());
		}
	}
}
