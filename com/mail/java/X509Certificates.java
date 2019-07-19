package com.mail.java;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;

public class X509Certificates {
	static Map<String, String> extensionEncodings = new HashMap<String, String>();
	// https://pki-tutorial.readthedocs.io/en/latest/mime.html
	// https://helpdesk.ssls.com/hc/en-us/articles/204093372-What-are-certificate-formats-and-what-is-the-difference-between-them-
	// * https://knowledge.digicert.com/generalinformation/INFO4448.html
	static {
		extensionEncodings.put(".JKS", "JKS");
		// PKCS stands for "Public Key Cryptography Standards" - https://en.wikipedia.org/wiki/PKCS
		// PKCS#12 bundles of private key + certificate(s)
		extensionEncodings.put(".PFX", "PKCS12");
		extensionEncodings.put(".P12", "PKCS12");
		// PKCS#7 bundles of two or more certificates, not the private key
		extensionEncodings.put(".P7B", "PKCS7");
		extensionEncodings.put(".P7C", "PKCS7");
		// PEM Format - Extensions used for PEM certificates are .crt, .pem, .key files
		// DER formatted certificates most often use the ‘.cer’ and '.der' extensions
	}
	public static String getFileExtension(String keyStoreFile) {
		String fileExtension = keyStoreFile.substring(keyStoreFile.lastIndexOf('.'), keyStoreFile.length());
		Log4J.log("File Extension : "+ fileExtension);
		return fileExtension;
	}
	public static KeyStore getKeyStore(String keyStoreFile) throws KeyStoreException, NoSuchProviderException {
		addBCMimeContent();
		// https://docs.oracle.com/javase/6/docs/technotes/tools/windows/keytool.html#KeyStore%20Implementation
		String fileExtension = getFileExtension(keyStoreFile);
		String extension = fileExtension.toUpperCase();
		if(extensionEncodings.containsKey(extension)) {
			String encodingFormat = extensionEncodings.get(extension);
			Log4J.log("Extension:["+extension+"] KeyStore Format- : "+ encodingFormat);
			if (extension.equals(".JKS")) {
				return KeyStore.getInstance( KeyStore.getDefaultType() );
			}
			return KeyStore.getInstance(encodingFormat, EMail.EMAIL_PROVIDER.getValue());
		}
		return null;
	}
	
	protected static HashMap<String, Object> unLockToGetCertificates(InputStream is, String password) {
		HashMap<String, Object> certMap = new HashMap<String, Object>();
		try {
			KeyStore keystore = X509Certificates.getKeyStore(EMail.CERTIFICATE_FILE.getValue());
			// Loads this KeyStore from the given input stream and unlock from the given password.
			keystore.load(is, password.toCharArray());
			String aliasName = getAliasName(keystore);
			
			// https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/x509/X509CertImpl.java
			PrivateKey privateKey_PEM = (PrivateKey) keystore.getKey(aliasName, password.toCharArray());
			X509Certificate signCert = getX509Certificate(true, keystore, aliasName, "");
			
			certMap.put("keystore", keystore);
			certMap.put("signCert", signCert);
			certMap.put("privateKey", privateKey_PEM);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return certMap;
	}
	public static String getAliasName(KeyStore keystore) throws KeyStoreException {
		String aliasName = null;
		// Per file contains one alias name.
		Enumeration<String> keyStoreAliasEnum = keystore.aliases();
		boolean isFirst = true;
		while (keyStoreAliasEnum.hasMoreElements()) {
			if (isFirst) {
				isFirst = false;
				aliasName = keyStoreAliasEnum.nextElement();
				EMail.ALIAS_NAME.setValue(aliasName);
				Log4J.log("Certificate To Use Alias : "+ EMail.ALIAS_NAME.getValue());
			} else {
				Log4J.log("Certificate Alias : "+ keyStoreAliasEnum.nextElement());
			}
		}
		return aliasName;
	}
	/*
	In the case of a certificate factory for X.509 certificates, the certificate provided in inStream must be 
	DER-encoded and may be supplied in binary or printable (Base64) encoding. 
	If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 -----BEGIN CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----.   
	 */
	public static X509Certificate getX509Certificate(boolean isDEREncoded, KeyStore keystore, String alias, String fileName) throws Exception {
		CertificateFactory certFactory= CertificateFactory.getInstance(EMail.CERTIFICATE_TYPE.getValue(), EMail.EMAIL_PROVIDER.getValue());
		
		InputStream is = null;
		if (isDEREncoded) { // X.690 « DER-encoded and may be supplied in binary. Private key in Encoded format
			// Distinguished Encoding Rules (DER) - https://en.wikipedia.org/wiki/X.690#DER_encoding
			Certificate certificate = keystore.getCertificate(alias);
			is = new ByteArrayInputStream(certificate.getEncoded());
		} else { // X.509 « *.cer,*.pem file contains printable (Base64) encoding. Private key in PEM format
			// Privacy-Enhanced Mail (PEM) - 
			is = new FileInputStream(fileName);
		}
		X509Certificate signCert = (X509Certificate) certFactory.generateCertificate(is);
		return signCert;
	}
	
	public static void configure_JCE_UnlimitedStrength() {
		Log4J.log("Java Cryptography Extension Unlimited Strength Jurisdiction Policy Files");
		try {
			int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
			Log4J.log("Max Key Size for AES : " + maxKeySize); // Default-128
			if (maxKeySize == 128) { // For java versio less than 9
				Log4J.log("Link: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html");
				Log4J.log("Download these jars(local_policy.jar,US_export_policy.jar) and replace in {JAVA_HOME}/lib/security.");
			}
			
			// For java 9 - Added Encryption policy(local or USExport).
			Security.setProperty("crypto.policy", "unlimited");
		} catch (java.security.NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	// Content-Type: application/pkcs7-signature; name=smime.p7s; smime-type=signed-data
	// Content-Description: S/MIME Cryptographic Signature
	public static void addBCMimeContent() {
		MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
		mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
		CommandMap.setDefaultCommandMap(mailcap);
		
		// java.security.NoSuchProviderException: no such provider: BC
		addBCProvider();
	}
	public static void addBCProvider() {
		// java.security.NoSuchProviderException: no such provider: BC
		if (Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
			Log4J.log("JVM Installing BouncyCastle Security Providers to the Runtime");
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} else {
			Log4J.log("JVM Installed with BouncyCastle Security Providers");
		}
		
		/*Provider[] pArr = Security.getProviders();
		int i = 0;
		for (Provider p : pArr) {
			Log4J.log((i++) + " - provider ::" + p.getName());
		}*/
		
		configure_JCE_UnlimitedStrength();
	}
	
	public static void main(String[] args) throws KeyStoreException, NoSuchProviderException {
		getKeyStore("MyServer.jks");
	}
}
