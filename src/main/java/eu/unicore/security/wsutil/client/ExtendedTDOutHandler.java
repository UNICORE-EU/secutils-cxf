/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 17-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.client;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.InconsistentTDChainException;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.user.UserAssertion;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.ETDClientSettings;
import eu.unicore.util.httpclient.IClientConfiguration;


/**
 * Trust delegation handler for outgoing messages. It extends generic {@link TDOutHandler}.
 * The implementation can configure underlying handler in two cases:
 * <ul>
 * <li>a (list of) trust delegation assertion(s) is passed on</li>
 * <li>if requested a new trust delegation assertion is generated 
 * (which may extend an existing one)</li>
 * </ul>
 * 
 * @author K. Benedyczak
 * @author schuller
 */
public class ExtendedTDOutHandler extends TDOutHandler 
{
	private static final Logger logger = Log.getLogger(Log.SECURITY,ExtendedTDOutHandler.class);

	private List<TrustDelegation> assertionList=null;
	private UserAssertion userAssertion=null;

	/**
	 * Initialise the handler. The supplied security properties 
	 * may contain an existing list of trust delegations. <br/>
	 * If configured in the ETD settings, a new assertion will be generated (and an existing chain will be extended.) 
	 * In this case	the ETD settings should contain the name of the receiver.<br/>
	 * Else, the supplied TD chain will be used as-is.
	 */
	public ExtendedTDOutHandler(IClientConfiguration config)
	{
		ETDClientSettings sec = config.getETDSettings();
		X509Certificate[] issuer = sec.getIssuerCertificateChain();
		if ((issuer == null || issuer.length == 0) && sec.getRequestedUser() == null)
		{
			logger.debug("Neither issuer was set, nor requestedUser. Won't add any ETD/User assertion");
			return;
		}
		String issuerDN = (issuer != null && issuer.length > 0) ? issuer[0].getSubjectX500Principal().getName()
				: sec.getRequestedUser();

		assertionList=sec.getTrustDelegationTokens() != null ? 
			sec.getTrustDelegationTokens() : new ArrayList<TrustDelegation>();
		if(sec.isExtendTrustDelegation()){
			try
			{
				setupExtendedAssertionList(config);
			}
			catch(Exception dse)
			{
				throw new RuntimeException("Error setting up (extended) TD chain", dse);
			}
		}
		logger.debug("Initialised TD Outhandler, TD chain length = "+assertionList.size());

		String requestedUser = sec.getRequestedUser();
		if (requestedUser == null)
		{
			//first try to get one from the ETD chain:
			if (assertionList.size() > 0)
				requestedUser = assertionList.get(0).getCustodianDN();
			//if no ETD chain, then use our local identity
			else
				requestedUser = issuerDN;
		}

		if (needCustomUserAssertion(sec))
		{
			userAssertion=super.createUserAssertion(null, requestedUser, issuerDN);
			//add requested attributes
			for(Map.Entry<String,String[]> e: sec.getRequestedUserAttributes2().entrySet()){
				SAMLAttribute at = new SAMLAttribute(e.getKey(),
						ETDClientSettings.SAML_ATTRIBUTE_REQUEST_NAMEFORMAT);
				for (String val: e.getValue())
					at.addStringAttributeValue(val);
				userAssertion.addAttribute(at);
			}
			//set up handler to use a provided user assertion
			super.init(assertionList, userAssertion);
		} else
		{
			super.init(assertionList, null, requestedUser, issuerDN);
		}
	}

	private void setupExtendedAssertionList(IClientConfiguration config)
			throws DSigException, InconsistentTDChainException
			{
		ETDClientSettings sec = config.getETDSettings();
		X509Certificate[] issuer = sec.getIssuerCertificateChain();

		PrivateKey pk = config.getCredential().getKey();
		X500Principal receiver=sec.getReceiver();
		if(receiver==null){
			logger.debug("No receiver set, not creating TD assertion.");
		}
		else{
			String receiverName = receiver.getName();
			DelegationRestrictions restrictions = sec.getDelegationRestrictions();
			if (sec.getRelativeDelegationValidityDays() != null)
			{
				Calendar start = Calendar.getInstance();
				start.add(Calendar.HOUR, -1);
				Calendar end = Calendar.getInstance();
				end.add(Calendar.DAY_OF_YEAR, sec.getRelativeDelegationValidityDays());
				restrictions.setNotBefore(start.getTime());
				restrictions.setNotOnOrAfter(end.getTime());
			}
			if(assertionList.size()==0){
				assertionList.add(createAssertion(issuer,pk,receiverName,restrictions));
			}
			else{
				assertionList=extendAssertion(assertionList, issuer, pk, receiverName, restrictions);
			}

			if(logger.isDebugEnabled()){
				logger.debug("Initialised trust delegation to receiver <" +
						X500NameUtils.getReadableForm(receiverName)+">");
			}
		}
			}

	private boolean needCustomUserAssertion(ETDClientSettings sec){
		return sec!=null && (sec.getRequestedUserAttributes2().size() > 0);
	}

	/**
	 * create a new TD assertion
	 * 
	 * @param issuer - the entity issuing the assertion
	 * @param pk - the private key to be used for signing
	 * @param receiver - the X500 name of the receiver
	 * @param restrictions - any restrictions on the assertion (e.g. max length of delegation chain)
	 */
	protected synchronized TrustDelegation createAssertion(X509Certificate[] issuer, PrivateKey pk, 
			String receiver, DelegationRestrictions restrictions) throws DSigException
			{
		ETDApi engine = UnicoreSecurityFactory.getETDEngine();
		return engine.generateTD(issuer[0].getSubjectX500Principal().getName(), 
				issuer, pk, 
				receiver, 
				restrictions);
			}

	/**
	 * extend an existing the TD assertion
	 * 
	 * @param tdList - the existing list (length must be larger than 0!)
	 * @param issuer - the entity issuing the assertion
	 * @param pk - the private key to be used for signing
	 * @param receiver - the X500 name of the receiver
	 * @param restrictions - any restrictions on the assertion (e.g. max length of delegation chain)
	 */
	protected synchronized List<TrustDelegation> extendAssertion(List<TrustDelegation> tdList, X509Certificate[] issuer, PrivateKey pk, 
			String receiver, DelegationRestrictions restrictions)
					throws DSigException, InconsistentTDChainException
					{
		//check for duplicate receiver
		int l=tdList.size();
		String lastReceiver=tdList.get(l-1).getSubjectName();
		if(receiver.equals(lastReceiver)){
			logger.debug("TD chain already includes receiver <"+receiver+">");
			return tdList;
		}

		logger.debug("Extending TD chain to receiver <"+receiver+">");
		ETDApi engine = UnicoreSecurityFactory.getETDEngine();
		return engine.issueChainedTD(tdList,
				issuer, 
				pk, 
				receiver, 
				restrictions);
					}

	public List<TrustDelegation>getAssertionList(){
		return assertionList;
	}
	public UserAssertion getUserAssertion(){
		return userAssertion;
	}
}
