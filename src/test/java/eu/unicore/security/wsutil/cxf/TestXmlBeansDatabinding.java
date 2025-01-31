package eu.unicore.security.wsutil.cxf;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.StringReader;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

import org.junit.jupiter.api.Test;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

public class TestXmlBeansDatabinding {

	@Test
	public void testXmlBeansDatabinding() throws Exception {
		DataReaderImpl dr = new DataReaderImpl();
		AssertionDocument ad = AssertionDocument.Factory.newInstance();
		ad.addNewAssertion().setID("123");
		String doc = ad.toString();
		XMLInputFactory factory = XMLInputFactory.newInstance();
		XMLStreamReader r = factory.createXMLStreamReader(new StringReader(doc));
		Object o = dr.doRead(r, null, AssertionDocument.class, null, false);
		assertNotNull(o);
		assertTrue(AssertionDocument.class.isAssignableFrom(o.getClass()));
	}

}
