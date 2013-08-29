/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.ws.WebServiceException;

import xmlbeans.org.oasis.saml2.assertion.AuthnContextType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationDataType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.wsutil.client.ClientTrustDelegationUtil;
import eu.unicore.security.wsutil.client.SAMLAttributePushOutHandler;

/**
 * Tests UNICORE 7 features: bootstrap ETD, when custodian and initial issuers are different 
 * and SAML authentication. Also both features used at the same time are tested here.
 *  
 * @author K. Benedyczak
 */
public class TestU7Security extends AbstractTestBase
{
	/**
	 * Client1 authenticating with SAML. Should be accepted.
	 */
	public void testSAMLAuthn()
	{
		try
		{
			System.out.println("\nTest regular SAML authn\n");
			Assertion authAssertion = createAuthenticationAssertion(MockSecurityConfig.CLIENT1_CRED, 
					MockSecurityConfig.SERVER_CRED, MockSecurityConfig.IDP_CRED);
			MockSecurityConfig config = new MockSecurityConfig(false, false, true);
			config.getExtraSecurityTokens().put(SAMLAttributePushOutHandler.PUSHED_ASSERTIONS, 
					Collections.singletonList(authAssertion));
			SimpleSecurityService s = makeProxy(config);

			String consignorRet = s.TestConsignor();

			assertTrue("Got " + consignorRet + " should get " + 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName(), 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName().equals(consignorRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	/**
	 * Client1 authenticating with wrong SAML. Shouldn't be accepted as assertion is issued by untrusted IdP.
	 */
	public void testWrongSAMLAuthn()
	{
		try
		{
			System.out.println("\nTest wrong SAML authn\n");
			Assertion authAssertion = createAuthenticationAssertion(MockSecurityConfig.CLIENT1_CRED, 
					MockSecurityConfig.SERVER_CRED, MockSecurityConfig.SERVER_CRED);
			MockSecurityConfig config = new MockSecurityConfig(false, false, true);
			config.getExtraSecurityTokens().put(SAMLAttributePushOutHandler.PUSHED_ASSERTIONS, 
					Collections.singletonList(authAssertion));
			SimpleSecurityService s = makeProxy(config);

			String consignorRet = s.TestConsignor();
			fail("Authenticated as " + consignorRet + " while should fail");
		} catch (WebServiceException e)
		{
			//OK
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	
	/**
	 * Client1 authenticating with cert is presenting bootstrap delegation 
	 * issued by IDP, for him, on behalf of client2 (the custodian). Should be accepted.
	 */
	public void testCorrectTDValidation()
	{
		try
		{
			System.out.println("\nTest regular Bootstrap TD validation\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(MockSecurityConfig.IDP_CRED,
					MockSecurityConfig.CLIENT2_CRED,
					MockSecurityConfig.CLIENT1_CRED);
			String receiver = MockSecurityConfig.CLIENT1_CRED.getSubjectName();
			ClientTrustDelegationUtil.addTrustDelegation(s, tds, 
					MockSecurityConfig.CLIENT2_CRED.getCertificate(), 
					receiver);

			String effUserRet = s.TestEffectiveUser();
			String consignorRet = s.TestConsignor();

			String issuer = MockSecurityConfig.CLIENT2_CRED.getSubjectName();

			assertTrue("Got " + effUserRet + " should get " + issuer, 
					issuer.equals(effUserRet));
			assertTrue(receiver.equals(consignorRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}

	/**
	 * Client1 authenticating with cert is presenting bootstrap delegation 
	 * issued by server, for him, on behalf of client2 (the custodian). Should not be accepted as 
	 * server is not trusted IDP.
	 */
	public void testIncorrectTDValidation()
	{
		try
		{
			System.out.println("\nTest wrong bootstrap TD: wrong initial issuer\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(MockSecurityConfig.SERVER_CRED,
					MockSecurityConfig.CLIENT2_CRED,
					MockSecurityConfig.CLIENT1_CRED);
			String receiver = MockSecurityConfig.CLIENT1_CRED.getSubjectName();
			ClientTrustDelegationUtil.addTrustDelegation(s, tds, 
					MockSecurityConfig.CLIENT2_CRED.getCertificate(), 
					receiver);

			String effUserRet = s.TestEffectiveUser();
			String consignorRet = s.TestConsignor();

			String issuer = MockSecurityConfig.CLIENT1_CRED.getSubjectName();

			assertTrue("Got " + effUserRet + " should get " + issuer, 
					issuer.equals(effUserRet));
			assertTrue(receiver.equals(consignorRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	/**
	 * Tests a typical certificate-less web service client case: it is authenticating with
	 * SAML and presenting a bootstrap delegation. However the delegation is for future use - it
	 * is not required to serve the executed request.
	 */
	public void testSAMLAuthnAndBootstrapETD()
	{
		try
		{
			System.out.println("\nTest regular SAML authn with bootstrap ETD push\n");
			Assertion authAssertion = createAuthenticationAssertion(MockSecurityConfig.CLIENT1_CRED, 
					MockSecurityConfig.SERVER_CRED, MockSecurityConfig.IDP_CRED);
			MockSecurityConfig config = new MockSecurityConfig(false, false, true);
			config.getExtraSecurityTokens().put(SAMLAttributePushOutHandler.PUSHED_ASSERTIONS, 
					Collections.singletonList(authAssertion));
			
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(MockSecurityConfig.IDP_CRED,
					MockSecurityConfig.CLIENT1_CRED,
					MockSecurityConfig.SERVER_CRED);
			ClientTrustDelegationUtil.addTrustDelegation(s, tds, 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName(), 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName());
			
			String consignorRet = s.TestConsignor();
			String userRet = s.TestEffectiveUser();
			assertTrue("ETD is invalid", "true".equals(s.TestETDValid()));

			assertTrue("Got " + consignorRet + " should get " + 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName(), 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName().equals(consignorRet));
			assertTrue("Got " + userRet + " should get " + 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName(), 
					MockSecurityConfig.CLIENT1_CRED.getSubjectName().equals(userRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}

	
	
	protected Assertion createAuthenticationAssertion(X509Credential asWho, X509Credential target,
			X509Credential issuer) throws Exception
	{
		AuthnContextType authContext = AuthnContextType.Factory.newInstance();
		authContext.setAuthnContextClassRef(SAMLConstants.SAML_AC_UNSPEC);
		Assertion assertion = new Assertion();
		assertion.setIssuer("TEST IdP",	SAMLConstants.NFORMAT_ENTITY);
		Subject subject = new Subject(asWho.getSubjectName(), SAMLConstants.NFORMAT_DN);
		setBearerSubjectConfirmation(subject.getXBean());
		assertion.setSubject(subject.getXBean());
		assertion.addAuthStatement(Calendar.getInstance(), authContext);
		assertion.setAudienceRestriction(new String[] {target.getSubjectName()});

		assertion.sign(issuer.getKey(), issuer.getCertificateChain());
		return assertion;
	}
	
	protected void setBearerSubjectConfirmation(SubjectType requested)
	{
		SubjectConfirmationType subConf = SubjectConfirmationType.Factory.newInstance();
		subConf.setMethod(SAMLConstants.CONFIRMATION_BEARER);
		SubjectConfirmationDataType confData = subConf.addNewSubjectConfirmationData();
		//TODO - this needs a decision - unsolicited or not...
		//confData.setInResponseTo(null);
		Calendar validity = Calendar.getInstance();
		validity.setTimeInMillis(System.currentTimeMillis() + 100000);
		confData.setNotOnOrAfter(validity);
		String consumerServiceURL = jetty.getUrls()[0].toExternalForm();
		confData.setRecipient(consumerServiceURL);
		requested.setSubjectConfirmationArray(new SubjectConfirmationType[] {subConf});
	}
	
	/**
	 * Creates a 1 element long bootstrap TD.  
	 * @param mode
	 * @return
	 * @throws Exception
	 */
	private List<TrustDelegation> createTD(X509Credential bootstrapCredential,
			X509Credential custodianCredential, X509Credential targetCredential) throws Exception
	{
		List<TrustDelegation> tds = new ArrayList<TrustDelegation>();
		ETDApi etdEngine = UnicoreSecurityFactory.getETDEngine();
		
		TrustDelegation td = etdEngine.generateBootstrapTD(
				custodianCredential.getSubjectName(), 
				bootstrapCredential.getCertificateChain(),
				"TEST IdP", SAMLConstants.NFORMAT_ENTITY,
				bootstrapCredential.getKey(),
				targetCredential.getSubjectName(),
				new DelegationRestrictions(new Date(), new Date(System.currentTimeMillis()+100000), 0));
		tds.add(td);
		return tds;
	}
}