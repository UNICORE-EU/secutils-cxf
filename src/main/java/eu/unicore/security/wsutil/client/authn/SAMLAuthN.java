/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.assertion.AttributeAssertionParser;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.canl.PasswordCallback;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.wsutil.client.SAMLAttributePushOutHandler;
import eu.unicore.security.wsutil.samlclient.AuthnResponseAssertions;
import eu.unicore.security.wsutil.samlclient.SAMLAuthnClient;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.ETDClientSettings;
import eu.unicore.util.httpclient.SessionIDProviderImpl;

/**
 * SAML SOAP binding based authentication. SAML authN assertion along with other assertions
 * (attribute, delegation) are obtained from SAML IdP (typically Unity).
 * <p>
 * Note that currently the implementation doesn't take into account specified delegation restriction (as lifetime):
 * always the restriction placed by the IdP are used.
 * <p>
 * To improve performance it is best to cache assertions retrieved from the IdP and reuse them for subsequent calls.
 * This implementation can be enriched with an {@link AssertionsCache} implementation, which can implement this feature
 * (in memory only or disk persistent mode). 
 * <p>
 * The class is thread safe.
 * 
 * @author K. Benedyczak
 */
public class SAMLAuthN extends PropertiesBasedAuthenticationProvider
{
	public static final String NAME = "unity";
	
	protected UsernameCallback usernameCallback;
	protected AssertionsCache assertionsCache;

	public SAMLAuthN(Properties properties, PasswordCallback passwordCallback, UsernameCallback usernameCallback,
			AssertionsCache assertionsCache)
	{
		super(properties, passwordCallback);
		this.usernameCallback = usernameCallback;
		this.assertionsCache = assertionsCache;
	}
	
	protected SAMLAuthN()
	{
	}
	
	@Override
	public String getName()
	{
		return NAME;
	}

	@Override
	public String getDescription()
	{
		return "Authenticate with login and password in Unity service. " +
				"Obtained SAML credentials are locally stored and used until expire. " +
				"For this method truststore must be properly configured but keystore/certificate " +
				"credential is not used.";
	}

	@Override
	public DefaultClientConfiguration getClientConfiguration(String targetAddress,
			String targetDn, DelegationSpecification delegate) throws Exception
	{
		SAMLAuthNProperties samlConfig = new SAMLAuthNProperties(properties);
		DefaultClientConfiguration baseClientConfiguration = getAnonymousClientConfiguration();

		if (targetAddress == null)
			throw new IllegalArgumentException("SAMLAuthN always require target service address");
		String idpAddress = samlConfig.getValue(SAMLAuthNProperties.ADDRESS);
		targetAddress = SessionIDProviderImpl.extractServerID(targetAddress);
		
		AuthnResponseAssertions samlResponse = assertionsCache.get(getKey(targetAddress, targetDn));
		if (samlResponse == null)
		{
			samlResponse = doSAMLAuthn(getUsername(samlConfig), 
					getPassword(samlConfig), idpAddress, targetDn,
					targetAddress, baseClientConfiguration);
			assertionsCache.store(getKey(targetAddress, targetDn), samlResponse);
		}
		return buildFinalSettings(samlResponse, baseClientConfiguration, delegate);
	}


	@Override
	public String getUsage()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("The following properties can be used in the UCC preference file " +
				"to configure the Unity/SAML authentication. Many of these are optional. Refer to the " +
				"manual and/or the example files.\n");
		sb.append(getMeta(SAMLAuthNProperties.class, SAMLAuthNProperties.PREFIX));

		sb.append("\nFor configuring your trusted CAs:\n");
		sb.append(getMeta(TruststoreProperties.class, TruststoreProperties.DEFAULT_PREFIX));
		return sb.toString();
	}

	
	/**
	 * Authenticates with SAML AuthN at the given endpoint and receives SAML assertions.
	 * If the target identity is not set (null) then query issuer identity is set to ENTITY Saml type 
	 * and to the targetUrl value. Otherwise it is set to the target identity DN.
	 * @param username
	 * @param password
	 * @param idpAddress
	 * @param anonymousClientCfg
	 * @throws MalformedURLException 
	 * @throws SAMLValidationException 
	 */
	private AuthnResponseAssertions doSAMLAuthn(String username, char[] password, 
			String idpAddress, String targetIdentity, String targetUrl, 
			DefaultClientConfiguration anonymousClientCfg) throws MalformedURLException, SAMLValidationException
	{
		anonymousClientCfg.setHttpAuthn(true);
		anonymousClientCfg.setHttpPassword(String.valueOf(password));
		anonymousClientCfg.setHttpUser(username);
		SAMLAuthnClient client = new SAMLAuthnClient(idpAddress, anonymousClientCfg);
		
		NameID requester;
		if (targetIdentity != null)
			requester = new NameID(targetIdentity, SAMLConstants.NFORMAT_DN);
		else
			requester = new NameID(targetUrl, SAMLConstants.NFORMAT_ENTITY);
		return client.authenticate(SAMLConstants.NFORMAT_DN, requester, targetUrl);
	}
	
	private String getKey(String targetAddress, String targetDn)
	{
		return targetDn == null ? "" : X500NameUtils.getComparableForm(targetDn) + "|||||" + targetAddress;
	}
	
	/**
	 * Build final client configuration with the provided assertions. Attribute and authN assertions
	 * are put into context so {@link SAMLAttributePushOutHandler} can pick them up.
	 * ETD assertions are separately configured.
	 * @param response
	 * @param baseClientConfiguration
	 * @return
	 * @throws IOException 
	 */
	private DefaultClientConfiguration buildFinalSettings(AuthnResponseAssertions response, 
			DefaultClientConfiguration baseClientConfiguration, DelegationSpecification delegate) 
					throws IOException
	{
		List<AssertionParser> authNAssertions = response.getAuthNAssertions();
		List<AssertionDocument> otherAssertions = response.getOtherAssertions();
		List<AttributeAssertionParser> attributeAssertions = response.getAttributeAssertions();

		DefaultClientConfiguration ret = baseClientConfiguration.clone();
		
		List<Assertion> assertionsToBePushed = new ArrayList<Assertion>();
		List<TrustDelegation> tds = new ArrayList<TrustDelegation>();
		if (authNAssertions.size() != 1)
		{
			throw new IOException("SAML service returned " + authNAssertions.size() + " authentication " +
					"assertions. We need exactly one - this service is unsupported.");
		} else
		{
			AssertionDocument authnAssertionXml = authNAssertions.get(0).getXMLBeanDoc();
			assertionsToBePushed.add(new Assertion(authnAssertionXml));
		}
		for (AttributeAssertionParser attributeAssertion: attributeAssertions)
		{
			AssertionDocument attributeAssertionXml = attributeAssertion.getXMLBeanDoc();
			try
			{
				TrustDelegation td = new TrustDelegation(attributeAssertionXml);
				tds.add(td);
			} catch (Exception e)
			{
				//not a TD, OK
				assertionsToBePushed.add(new Assertion(attributeAssertionXml));
			}
		}
		
		if (otherAssertions.size() > 0)
		{
			System.out.println("SAML service returned some unknown assertions which are " +
					"neither attribute nor authentication assertions. Those assertions will be ignored.");
		}
		
		ret.getExtraSecurityTokens().put(SAMLAttributePushOutHandler.PUSHED_ASSERTIONS, assertionsToBePushed);
		
		if (delegate.isDelegate())
		{
			if (tds.isEmpty())
			{
				throw new IOException("Trust delegation was not found in the received assertions. " +
					"Probably you are using a UNICORE unaware SAML service.");
			} else if (tds.size() > 1)
				throw new IOException("Multiple trust delegations were found in the received assertions. " +
					"This is unsupported.");
			ETDClientSettings etdSettings = ret.getETDSettings();
			etdSettings.setTrustDelegationTokens(Collections.singletonList(tds.get(0)));
			etdSettings.setRequestedUser(tds.get(0).getCustodianDN());
		}
		return ret;
	}

	private String getUsername(SAMLAuthNProperties stsConfig) throws IOException
	{
		String ret = stsConfig.getValue(SAMLAuthNProperties.USERNAME);
		if (ret == null)
			return usernameCallback.getUsername();
		return ret;
	}
	
	private char[] getPassword(SAMLAuthNProperties stsConfig)
	{
		String ret = stsConfig.getValue(SAMLAuthNProperties.PASSWORD);
		if (ret == null)
			return truststorePasswordCallback.getPassword("login", "Unity password");
		return ret.toCharArray();
	}
	
	protected void setAssertionsCache(AssertionsCache cacheImpl)
	{
		this.assertionsCache = cacheImpl;
	}
}
