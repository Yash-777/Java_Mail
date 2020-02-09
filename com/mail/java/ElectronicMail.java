package com.mail.java;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.io.IOUtils;
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

@SuppressWarnings("all")
public class ElectronicMail {
	private final static Log log = LogFactory.getLog(ElectronicMail.class);
	
	private static String TO_ADDRESS = EMail.TO_ADDRESS.getValue();
	
	public static void main(String[] args) throws IOException {
		
		tetMail(false, true);
		
	}
	public static void consoleLog(String msg) {
		System.out.println(msg);
		log.info(msg);
	}
	public static boolean isStoreMessage = true, auth = false;
	public static void tetMail(boolean isClassPath, boolean isSigned) {
		String subject = "Testing Subject";
		String electronic_Message = "MIME message Body - Test Mail using JavaMailAPI";
		if( sendMail(subject, electronic_Message, TO_ADDRESS, isSigned, isClassPath) ) {
			consoleLog("Sent message successfully.");
		} else {
			consoleLog("message failed.");
		}
	}
	public static boolean useAttachementFile = false, signSecretMessage = false;
	// https://stackoverflow.com/q/24738657/5081877
	public static boolean sendMail(String subject, String body, String recipients, boolean isSigned, boolean isClassPath) {
		try {
			Session mailSession = getSessionObject(auth, EMail.PROTOCAL.getValue());
			consoleLog("getSessionObject. : "+mailSession.toString());
			// Create a default MimeMessage object.
			Message message = new MimeMessage( mailSession );
			message.setFrom( new InternetAddress( EMail.USER_NAME.getValue() ) );
			message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(TO_ADDRESS));
			message.setSubject( subject );
			
			//Simple Message - [Plain Text | HTML Content]
			String header_name = "Content-ID", header_value = "<b>";
			message.addHeader( header_name, header_value );
			
			if (isSigned) {
				MimeMultipart mm = getMultipart(isClassPath);
				
				if (useAttachementFile) {
					// Part two is attachment
					MimeBodyPart fileBodyPart = new MimeBodyPart();
					InputStream cerFileStream = getCerFileStream(true);
					File fileFromStream = getFileFromStream(cerFileStream);
					consoleLog("File : "+fileFromStream.getAbsolutePath());
					DataSource source = new javax.activation.FileDataSource( fileFromStream );
					fileBodyPart.setDataHandler( new DataHandler( source ) );
					fileBodyPart.setFileName( fileFromStream.getName() );
					mm.addBodyPart( fileBodyPart );
				}
				
				// Set the content of the signed message
				message.setContent(mm, mm.getContentType());
			} else {
				//byte[] signedData = signedData(body);
				message.setContent( body, "text/plain" );
			}
			message.saveChanges();
			consoleLog("Message is Ready to Send/Store.");
			
			if (isStoreMessage) {
				// https://github.com/protocol7/smime-java-example/blob/master/src/main/java/com/protocol7/smime/Sign.java
				message.writeTo(System.out);
				message.writeTo(new FileOutputStream(EMail.SAVE_MESSAGE.getValue()));
			} else {
				// Send message
				Transport transport = mailSession.getTransport(EMail.PROTOCAL.getValue());
				if (auth) {
					transport.connect(EMail.SMTP_HOST.getValue(), EMail.USER_NAME.getValue(), EMail.PASSWORD.getValue());
				} else {
					transport.connect();
				}
				transport.sendMessage(message, message.getAllRecipients());
				transport.close();
			}
			consoleLog("Message Sent/Stored Succesfully.");
			return true;
		} catch(Exception ex) {
			ex.printStackTrace();
			consoleLog(ex.getMessage());
		}
		return false;
	}
	public static InputStream getCerFileStream(boolean isClassPath) throws FileNotFoundException {
		InputStream stream = null;
		consoleLog("Certificate File : "+ EMail.CERTIFICATE_FILE.getValue());
		if (isClassPath) {
			isStoreMessage = false;
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			stream = classLoader.getResourceAsStream(EMail.CERTIFICATE_FILE.getValue());
		} else {
			stream = new FileInputStream(EMail.CERTIFICATE_FILE.getValue());
		}
		return stream;
	}
	// https://stackoverflow.com/a/34387472/5081877
	public static File getFileFromStream(InputStream in) throws IOException {
		File tempFile = File.createTempFile("MyServer", ".jks");
		tempFile.deleteOnExit();
		FileOutputStream out = new FileOutputStream(tempFile);
		IOUtils.copy(in, out); // org.apache.pdfbox.io.IOUtils
		return tempFile;
	}
	private static MimeMultipart getMultipart(boolean isClassPath) throws Exception {
		try {
			// -keystore "D:/Yash/MyServer.jks" -storetype JKS -keypass password -storepass password
		InputStream inputStream = getCerFileStream(isClassPath);
		String password = EMail.ALIAS_PASSWORD.toString(); // Scheduling_2018
		
		consoleLog("FIS : "+inputStream.available()+ " toString() : "+ inputStream.toString());
		
		// cryptographicOperations
		HashMap<String, Object> certificateData = buildCertificateAndGetPrivateKey(inputStream, password);
		if (!certificateData.isEmpty()) {
			X509Certificate x509Certificate = (X509Certificate) certificateData.get("certificate");
			PrivateKey privateKey_PEM = (PrivateKey) certificateData.get("privateKey");
			KeyStore keyStore = (KeyStore) certificateData.get("keystore");
			
			SMIMESignedGenerator gen = getSMIMEGenerator(x509Certificate, privateKey_PEM, keyStore, true);
			MimeBodyPart msg = new MimeBodyPart();
			String commonMSG = "Display Message - Not Signed";
			msg.setText(commonMSG);
			
			MimeMultipart mm = gen.generate(msg);
			
			if (signSecretMessage) {
				MimeBodyPart msg2 = new MimeBodyPart();
				msg2.setText(commonMSG);
				mm.addBodyPart(msg2);
			}
			
			return mm;
		}
		
		} catch (Exception e) {
			consoleLog("getMultipart : "+e.getMessage());
			throw new Exception(e);
		}
		return null;
	}
	
	protected static SMIMESignedGenerator getSMIMEGenerator(X509Certificate x509Certificate, PrivateKey privateKey_PEM, KeyStore keyStore, boolean usingCertificate) {
		try {
			ContentSigner contentSigner = 
					// new JcaContentSignerBuilder(EMail.SIGNATURE_AlgorithmIdentifier.getValue()).build(privateKey_PEM);
					new JcaContentSignerBuilder(x509Certificate.getSigAlgName()).build(privateKey_PEM);
			
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
				IssuerAndSerialNumber createIssuerAndSerialNumberFor = SMIMEUtil.createIssuerAndSerialNumberFor(x509Certificate);
				signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(createIssuerAndSerialNumberFor));
			} else { // KeyStore, KeyStore Alias
				// Load certificate chain
				Certificate[] chain = keyStore.getCertificateChain(EMail.ALIAS_NAME.getValue());
				X500Name x500 = new X500Name(((X509Certificate) chain[0]).getIssuerDN().getName());
				IssuerAndSerialNumber serialNumber = new IssuerAndSerialNumber(x500 ,  ((X509Certificate) chain[0]).getSerialNumber()) ;
				
				signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(serialNumber));
			}
			
			SMIMESignedGenerator gen = new SMIMESignedGenerator();
			//gen.addSigner(privateKey_PEM, x509Certificate, SMIMESignedGenerator.DIGEST_SHA1);
			gen.addSignerInfoGenerator(
					new JcaSimpleSignerInfoGeneratorBuilder().setProvider(EMail.EMAIL_PROVIDER.getValue())
						.setSignedAttributeGenerator(new AttributeTable(signedAttrs))
						.build(x509Certificate.getSigAlgName(), privateKey_PEM, x509Certificate));
					// .build(EMail.SIGNATURE_AlgorithmIdentifier.getValue(), privateKey_PEM, x509Certificate));
			
			consoleLog("**********************"+ x509Certificate.getSigAlgName());
			
			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			certList.add( x509Certificate );
			org.bouncycastle.util.Store certs = new JcaCertStore(certList);
			gen.addCertificates(certs);
			
			return gen;
		} catch (Exception e1) {
		}
		return null;
	}
	
	public static String getSignedMessage(X509Certificate signCert, PrivateKey privateKey_PEM, String secretMessage) throws CMSException, IOException, CertificateEncodingException, OperatorCreationException {
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add( signCert );
		Store<?> jcaCertStore = new JcaCertStore(certList);
		
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
		
		byte[] signedMessage = null;
		CMSTypedData cmsData= new CMSProcessableByteArray(secretMessage.getBytes());
		CMSSignedData cms = cmsGenerator.generate(cmsData, false);
		signedMessage = cms.getEncoded();
		return new String(signedMessage);
	}
	public static Session getSessionObject(boolean auth, String protocal) {
		if(protocal.equalsIgnoreCase("SMTPS") || protocal.equalsIgnoreCase("SMTP") ) {
			return getTransportSessionObject(auth, protocal);
		}
		return getStoreSessionObject(auth, protocal);
	}
	public static Session getStoreSessionObject(boolean auth, String storeProtocal) {
		return null;
	}

	public static Session getTransportSessionObject(boolean auth, String transportProtocal) {
		System.out.println("==- Outgoing Mail (SMTP) Server details like SMTP properties and Authenticate -==");
		Properties props = new Properties();
		if(transportProtocal.equalsIgnoreCase("SMTPS")) {
			props.put("mail.transport.protocol", "smtps");
			props.put("mail.smtp.starttls.enable", "true");
		} else {
			props.put("mail.transport.protocol", "smtp");
			props.put("mail.smtps.ssl.enable", "true");
			// props.put("mail.smtp.ssl.trust", "*");
		}
		props.put("mail.smtp.timeout", "60000");
		
		props.put("mail.smtp.host", EMail.SMTP_HOST.getValue());
		props.put("mail.smtp.port", EMail.SMTP_PORT.getValue());
		
		props.put("mail.smtp.socketFactory", "javax.net.ssl.SSLSocketFactory");
		props.put("mail.smtp.socketFactory.port", EMail.SMTP_PORT.getValue());
		props.put("mail.smtp.socketFactory.fallback", "false");
		props.put("mail.smtp.debug", "true");
		props.put("mail.smtp.quitwait", "false");
		
		// Get the Session object by Authenticating Password.
		if ( auth ){
			props.put("mail.smtp.auth", "true");
			
			props.put("mail.smtp.user", EMail.USER_NAME.getValue());
			props.put("mail.smtp.password", EMail.PASSWORD.getValue());
		} else {
			props.put("mail.smtp.auth", "false");
		}
		Session defaultInstance = Session.getDefaultInstance(props); // Session.getInstance(props);
		System.out.println("Session DefaultInstance : "+defaultInstance.toString());
		return defaultInstance;
	}
	protected static HashMap<String, Object> buildCertificateAndGetPrivateKey(InputStream is, String password) {
		HashMap<String, Object> certificateData = new HashMap<String, Object>();
		try {
			KeyStore keystore = getKeyStore(EMail.CERTIFICATE_FILE.getValue());
			keystore.load(is, password.toCharArray());
			String aliasName = getAliasName(keystore);
			
			// https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/x509/X509CertImpl.java
			// Signature Algorithm: 1.2.840.113549.1.1.10PSS Parameters, OID = 1.2.840.113549.1.1.10
			CertificateFactory certFactory= 
					CertificateFactory.getInstance(EMail.CERTIFICATE_TYPE.getValue(), EMail.EMAIL_PROVIDER.getValue());
			PrivateKey privateKey_PEM = (PrivateKey) keystore.getKey(aliasName, password.toCharArray());
			X509Certificate x509Certificate = getX509Certificate(certFactory, true, keystore, aliasName, "");
			
			consoleLog("-----------------------------"+x509Certificate);
			consoleLog("-----------------------------"+x509Certificate.getSigAlgName());
			consoleLog("-----------------------------"+x509Certificate.getSigAlgOID());
			//consoleLog("RSA Public Key --------------"+x509Certificate.getPublicKey());
			
			String thumbprint = getThumbprint(x509Certificate);
			consoleLog("-----------------------------"+ thumbprint);
			
			certificateData.put("keystore", keystore);
			certificateData.put("certificate", x509Certificate);
			certificateData.put("privateKey", privateKey_PEM);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return certificateData;
	}
	private static String getThumbprint(X509Certificate cert) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		String digestHex = DatatypeConverter.printHexBinary(digest);
		return digestHex.toLowerCase();
	}
	public static String getAliasName(KeyStore keystore) throws KeyStoreException {
		String aliasName = null;
		// Per file contains one alias name.
		Enumeration<String> keyStoreAliasEnum = keystore.aliases();
		if (keyStoreAliasEnum.hasMoreElements()) {
			aliasName = keyStoreAliasEnum.nextElement();
			EMail.ALIAS_NAME.setValue(aliasName);
		}
		consoleLog("Certificate Alias : "+ EMail.ALIAS_NAME.getValue());
		return aliasName;
	}
	/*
	In the case of a certificate factory for X.509 certificates, the certificate provided in inStream must be 
	DER-encoded and may be supplied in binary or printable (Base64) encoding. 
	If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 -----BEGIN CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----.   
	 */
	public static X509Certificate getX509Certificate(CertificateFactory certFactory, 
			boolean isDEREncoded, KeyStore keystore, String alias, String fileName) throws Exception {
		InputStream is = null;
		if (isDEREncoded) { // X.690 � DER-encoded and may be supplied in binary. Private key in Encoded format
			// Distinguished Encoding Rules (DER) - https://en.wikipedia.org/wiki/X.690#DER_encoding
			Certificate certificate = keystore.getCertificate(alias);
			is = new ByteArrayInputStream(certificate.getEncoded());
		} else { // X.509 � *.cer,*.pem file contains printable (Base64) encoding. Private key in PEM format
			// Privacy-Enhanced Mail (PEM) - 
			is = new FileInputStream(fileName);
		}
		X509Certificate signingCertificate = (X509Certificate) certFactory.generateCertificate(is);
		return signingCertificate;
	}

	public static String getFileExtension(String keyStoreFile) {
		String fileExtension = keyStoreFile.substring(keyStoreFile.lastIndexOf('.') + 1, keyStoreFile.length());
		consoleLog("File Extension : "+ fileExtension);
		return fileExtension;
	}
	public static KeyStore getKeyStore(String keyStoreFile) throws KeyStoreException, NoSuchProviderException {
		addBCContent();
		
		// https://docs.oracle.com/javase/6/docs/technotes/tools/windows/keytool.html#KeyStore%20Implementation
		String fileExtension = getFileExtension(keyStoreFile);
		if (fileExtension.equalsIgnoreCase("JKS")) {
			// java.security.KeyStoreException: JKS not found
			consoleLog("KeyStore - JKS : "+ EMail.KEYSTORE_TYPE.getValues()[0]);
			return KeyStore.getInstance( KeyStore.getDefaultType() );
		} else if (fileExtension.equalsIgnoreCase("P12") || fileExtension.equalsIgnoreCase("PFX")) {
			consoleLog("KeyStore - PKCS12 : "+ EMail.KEYSTORE_TYPE.getValues()[1]);
			return KeyStore.getInstance("PKCS12", EMail.EMAIL_PROVIDER.getValue());
		}
		
		return null;
	}
	public static void addBCContent() {
		MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
		mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
		CommandMap.setDefaultCommandMap(mailcap);
		
		// java.security.NoSuchProviderException: no such provider: BC
		addProvider();
	}
	public static void addProvider() {
		// Install BouncyCastle Security Providers to the Runtime
		// java.security.NoSuchProviderException: no such provider: BC
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		/*Provider[] pArr = Security.getProviders();
		int i = 0;
		for (Provider p : pArr) {
			consoleLog((i++) + " - provider ::" + p.getName());
		}*/
		
		configure_JCE_UnlimitedStrength();
	}
	public static void configure_JCE_UnlimitedStrength() {
		System.out.println("Java Cryptography Extension Unlimited Strength Jurisdiction Policy Files");
		try {
			int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
			consoleLog("Max Key Size for AES : " + maxKeySize); // Default-128
			
			// For java 9 - Added Encryption policy(local or USExport).
			//Security.setProperty("crypto.policy", "unlimited");
		} catch (java.security.NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
}
