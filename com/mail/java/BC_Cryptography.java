package com.mail.java;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class BC_Cryptography extends X509Certificates {

	private static Store<?> getJCACertStore(X509Certificate signCert) throws CertificateEncodingException {
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add( signCert );
		Store<?> jcaCertStore = new JcaCertStore(certList);
		return jcaCertStore;
	}
	protected static CMSSignedDataGenerator buildSignedDataGenerator(X509Certificate signCert, PrivateKey privateKey_PEM) throws CertificateEncodingException, OperatorCreationException, CMSException {
		Store<?> jcaCertStore = getJCACertStore(signCert);
		
		ContentSigner sha1Signer = 
				new JcaContentSignerBuilder(EMail.SIGNATURE_AlgorithmIdentifier.getValue())
					.setProvider("BC")
					.build(privateKey_PEM);
		
		// https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/cms/CMSSignedDataGenerator.html
		CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
		cmsGenerator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
					).build(sha1Signer, signCert));
		cmsGenerator.addCertificates(jcaCertStore);
		
		return cmsGenerator;
	}
	public static String getSignedMessage(X509Certificate signCert, PrivateKey privateKey_PEM, String secretMessage) throws CMSException, IOException, CertificateEncodingException, OperatorCreationException {
		CMSSignedDataGenerator cmsGenerator = buildSignedDataGenerator(signCert, privateKey_PEM);
		
		byte[] signedMessage = null;
		CMSTypedData cmsData= new CMSProcessableByteArray(secretMessage.getBytes());
		CMSSignedData cms = cmsGenerator.generate(cmsData, false);
		signedMessage = cms.getEncoded();
		return new String(signedMessage);
	}
	protected static SMIMESignedGenerator buildSignedGenerator(X509Certificate signCert, PrivateKey privateKey_PEM, KeyStore keyStore, boolean usingCertificate) {
		try {
			//ContentSigner contentSigner = new JcaContentSignerBuilder(EMail.SIGNATURE_AlgorithmIdentifier.getValue()).build(privateKey_PEM);
			
			// https://github.com/bcgit/bc-java/blob/master/mail/src/main/java/org/bouncycastle/mail/smime/SMIMESignedGenerator.java
			// Create the SMIMESignedGenerator
			SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
			capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
			capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
			capabilities.addCapability(SMIMECapability.dES_CBC);
			capabilities.addCapability(SMIMECapability.aES256_CBC);
			capabilities.addCapability(SMIMECapability.aES128_CBC);
			capabilities.addCapability(SMIMECapability.aES192_CBC);
			
			ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
			signedAttrs.add(new SMIMECapabilitiesAttribute(capabilities));
			
			if (usingCertificate) { // X509Certificate
				IssuerAndSerialNumber createIssuerAndSerialNumberFor = SMIMEUtil.createIssuerAndSerialNumberFor(signCert);
				signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(createIssuerAndSerialNumberFor));
			} else { // KeyStore, KeyStore Alias
				// Load certificate chain
				Certificate[] chain = keyStore.getCertificateChain(EMail.ALIAS_NAME.getValue());
				X509Certificate firstCert = (X509Certificate) chain[0];
				X500Name x500 = new X500Name(firstCert.getIssuerDN().getName());
				IssuerAndSerialNumber serialNumber = new IssuerAndSerialNumber(x500 , firstCert.getSerialNumber()) ;
				
				signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(serialNumber));
			}
			
			Store<?> jcaCertStore = getJCACertStore(signCert);
			
			SMIMESignedGenerator gen = new SMIMESignedGenerator();
			//gen.addSigner(privateKey_PEM, x509Certificate, SMIMESignedGenerator.DIGEST_SHA1);
			gen.addSignerInfoGenerator(
					new JcaSimpleSignerInfoGeneratorBuilder()
						.setProvider(EMail.EMAIL_PROVIDER.getValue())
						.setSignedAttributeGenerator(new AttributeTable(signedAttrs))
						.build(EMail.SIGNATURE_AlgorithmIdentifier.getValue(), privateKey_PEM, signCert));
			gen.addCertificates(jcaCertStore);
			
			/*CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
			cmsGenerator.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
						.setProvider(MailDomain.EMAIL_PROVIDER.getValue()).build()).build(contentSigner, x509Certificate));
			cmsGenerator.addCertificates(certs);
			
			Log4J.consoleLog("Original Message : " + secretMessage);
			byte[] data = secretMessage.getBytes();
			
			CMSTypedData cmsData= new CMSProcessableByteArray(data);
			CMSSignedData cms = cmsGenerator.generate(cmsData, true);
			byte[] signedMessage = cms.getEncoded();*/
			
			return gen;
		} catch (Exception e1) {
		}
		return null;
	}
	

}
