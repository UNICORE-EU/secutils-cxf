package eu.unicore.security.xfireutil;
/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 17-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Enumerates which operations on a SEI annotated with this annotation require
 * a digital signature.
 * @author golbi
 */
@Inherited
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface OperationsRequiringSignature {
	public String[] operations();
}
