/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.util.httpclient.DefaultClientConfiguration;


/**
 * @author K. Benedyczak
 */
public class MockSecurityConfig extends DefaultClientConfiguration
{
	public static final String HTTP_PASSWD = "123";
	public static final String HTTP_USER = "qwer";
	
	public static final String KS = "src/test/resources/client/client.jks";
	public static final String KS_PASSWD = "the!client";

	public static final String KS_ALIAS = "mykey";
	public static final String KS_ALIAS_GW = "gw";
	public static final String KS_ALIAS_WRONG = "mykey_wrong";
	
	private boolean correctSSLAuthN;
	
	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, boolean correctSSLAuthN) throws Exception
	{
		setSslEnabled(true);
		setDoSignMessage(true);
		setHttpAuthn(doHTTPAuthN);
		setSslAuthn(doSSLAuthN);
		setHttpPassword(HTTP_PASSWD);
		setHttpUser(HTTP_USER);
		this.correctSSLAuthN = correctSSLAuthN;
		setCredential(new KeystoreCredential(KS, 
				KS_PASSWD.toCharArray(), 
				KS_PASSWD.toCharArray(), 
				getKeystoreAlias(), 
				"JKS"));
		setValidator(new KeystoreCertChainValidator(KS, 
				KS_PASSWD.toCharArray(), 
				"JKS", 
				-1));
		
	}
	
	public static X509Credential getGatewayCredential() throws Exception
	{
		return new KeystoreCredential(MockSecurityConfig.KS, 
				MockSecurityConfig.KS_PASSWD.toCharArray(), 
				MockSecurityConfig.KS_PASSWD.toCharArray(), 
				MockSecurityConfig.KS_ALIAS_GW, 
				"JKS");
	}
	
	public String getKeystoreAlias()
	{
		if (correctSSLAuthN)
			return KS_ALIAS;
		return KS_ALIAS_WRONG;
	}

	public MockSecurityConfig clone()
	{
		try
		{
			MockSecurityConfig ret = new MockSecurityConfig(doHttpAuthn(), doSSLAuthn(), correctSSLAuthN);
			ret.setClassLoader(getClassLoader());
			ret.setEtdSettings(getETDSettings().clone());
			ret.setExtraSecurityTokens(getExtraSecurityTokens());
			ret.setExtraSettings(getExtraSettings());
			ret.setInHandlerClassNames(getInHandlerClassNames());
			ret.setOutHandlerClassNames(getOutHandlerClassNames());
			return ret;
		} catch (Exception e)
		{
			throw new RuntimeException("Can't clone", e);
		}
	}

	@Override
	public String[] getOutHandlerClassNames()
	{
		return new String[] {AdditionalOutHandler.class.getName()};
	}

	@Override
	public String[] getInHandlerClassNames()
	{
		return new String[] {AdditionalInHandler.class.getName()};
	}

	public String getCertDN() throws Exception
	{
		return getCredential().getCertificate().getSubjectX500Principal().getName();
		
	}
}
