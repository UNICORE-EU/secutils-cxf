package eu.unicore.security.xfireutil;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates binding to use. If not specified on the service class, XmlBeans is
 * used.
 * 
 * @author schuller
 */
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Target(ElementType.TYPE)
@Inherited
public @interface XmlBinding {
	
	/**
	 * the name of the binding to use (jaxb, xmlbeans, ...)
	 * 
	 * @return
	 */
	public String name();

}
