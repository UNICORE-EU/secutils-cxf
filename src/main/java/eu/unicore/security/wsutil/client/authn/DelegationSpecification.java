/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil.client.authn;

import java.util.Date;

import eu.unicore.security.etd.DelegationRestrictions;

/**
 * Simple class allowing to set generic delegation. In future, if we want to use in practice restricted
 * delegation this class can be more configurable. Currently it only allow to set whether to delegate 
 * or not and the delegation lifetime. The delegation is set to have unlimited re-delegation number.
 * <p>
 * This class is different from the low level {@link DelegationRestrictions} as it governs whether to create delegation
 * or not and it is used to create new {@link DelegationRestrictions} at any time, while DelegationRestrictions
 * have absolute time boundaries.
 * 
 * @author K. Benedyczak
 */
public class DelegationSpecification
{
	private static final long DAY = 3600*24; 
	public static final DelegationSpecification DO_NOT = new DelegationSpecification(false, 0);
	public static final DelegationSpecification STANDARD = new DelegationSpecification(true, 14*DAY);
	
	private boolean delegate;
	private long lifetime;
	
	public DelegationSpecification(boolean delegate, long lifetime)
	{
		this.delegate = delegate;
		this.lifetime = lifetime;
	}

	public boolean isDelegate()
	{
		return delegate;
	}

	public void setDelegate(boolean delegate)
	{
		this.delegate = delegate;
	}

	public long getLifetime()
	{
		return lifetime;
	}

	public void setLifetime(long lifetime)
	{
		this.lifetime = lifetime;
	}
	
	/**
	 * @return delegation restrictions based on this class settings, suitable for the usage at the time 
	 * of calling the method.
	 */
	public DelegationRestrictions getRestrictions()
	{
		return new DelegationRestrictions(new Date(), 
				new Date(System.currentTimeMillis()+lifetime), -1);
	}
}
