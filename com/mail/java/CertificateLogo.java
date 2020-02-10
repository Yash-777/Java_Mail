package com.mail.java;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

public class CertificateLogo { // Code for JKS and PKCS12 certificates : All the parts of Mail are Signed/Encrypted.
	static MimeMessage message, signedMessage, finalMessage;
	static MimeBodyPart messageText;
	
	private final static Log log = LogFactory.getLog(CertificateLogo.class);
	public static void consoleLog(String msg) {
		System.out.println(msg);
		log.info(msg);
	}
	static List<ClassFile> attachments = new ArrayList<ClassFile>();
	static String FROM_ADDRESS, TO_ADDRESS;
	static Session session;
	public static void main(String[] args) throws Exception {
		String subject = "Message Sent on Date:" + (new Date());
		String body = "Hi, Test Mail";
		
		session = ElectronicMail.getSessionObject(true, EMail.PROTOCAL.getValue());
		message = new MimeMessage( session );
		message.setSentDate(new Date());
		
		FROM_ADDRESS = EMail.USER_NAME.getValue();
		TO_ADDRESS = EMail.TO_ADDRESS.getValue();
		
		message.setFrom( new InternetAddress( FROM_ADDRESS ) );
		consoleLog("From::" + FROM_ADDRESS + ":: " + Arrays.toString(message.getFrom()));

		message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(TO_ADDRESS));
		consoleLog("to::" + TO_ADDRESS + "" + message.getAllRecipients().toString());

		/*
		set the recipient of a carbon-copy and blind-carbon-copy of this mail.
		message.addRecipient(RecipientType.TO, new InternetAddress(TO_ADDRESS));
		message.addRecipient(RecipientType.CC, new InternetAddress(recipientId));
		message.addRecipient(RecipientType.BCC, new InternetAddress(recipientId));*/

		message.setSubject(subject);

		messageText = new MimeBodyPart();
		messageText.setText(body);

		ClassFile obj = new ClassFile();
		String fileName = EMail.CERTIFICATE_FILE.getValue();
		String password = EMail.ALIAS_PASSWORD.getValue();
		// java.io.IOException: PKCS12 key store mac invalid - wrong password or corrupted file.
		InputStream stream = getCerFileStream(false, fileName);
		certificateGen(stream, password);
		obj.setContentType("application/octet-stream");
		obj.setFileName(fileName);
		obj.setStream(stream);
		attachments.add(obj);
		
		Multipart multipartContent = new MimeMultipart();
			if (messageText != null) {
				multipartContent.addBodyPart(messageText);
			}

			if (attachments != null && attachments.size() > 0) {
				for (Iterator<ClassFile> it = attachments.iterator(); it.hasNext();) {
					ClassFile file = (ClassFile) it.next();
					multipartContent.addBodyPart(attachementBody(file));
				}
			}
		message.setContent(multipartContent);

		ByteArrayInputStream byteArrayInputStream = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		
		Enumeration headers = message.getAllHeaderLines();

		boolean attachementfile = true;
		
		if (attachementfile) {
			//MimeMessage signedMessage = null;
			boolean signMsg = true;
			boolean encryptMsg = true;
			if(signMsg) {
				MimeMultipart mimeMultipart = signer.generate(message);
				signedMessage = getSingnedMessage(headers, mimeMultipart, mimeMultipart.getContentType());
				if ( !encryptMsg) { // If no encryption, write to out
					mimeMultipart.writeTo(out);
				}
			} else {
				MimeBodyPart mimeBodyPart = signer.generateEncapsulated(message);
				signedMessage = getSingnedMessage(headers, mimeBodyPart, mimeBodyPart.getContentType());
				if ( !encryptMsg) { // If no encryption, write to out
					mimeBodyPart.writeTo(out);
				}
			}
			
			if (encryptMsg) {
				
				String publicCer = EMail.PUBLIC_KEY_FILE.getValue();
				File file = new File(publicCer);
				System.out.println("publicCer: "+file.getAbsolutePath());
				MimeBodyPart encryptedPart = getEncryptedPart(signedMessage, file.getAbsolutePath());
				encryptedPart.writeTo(out);
			}
			
				byteArrayInputStream = new ByteArrayInputStream(out.toByteArray());
				finalMessage = new MimeMessage(session, byteArrayInputStream);
				
				Enumeration headers2 = message.getAllHeaderLines();
				while (headers2.hasMoreElements()) {
					String headerLine = (String) headers2.nextElement();
					// Make sure not to override any content-* headers from the original message
					log.info("Headers::" + headerLine);
					if (!Strings.toLowerCase(headerLine).startsWith("content-")) {
						finalMessage.addHeaderLine(headerLine);
					}
				}
			//finalMessage.setContent(finalMessage, finalMessage.getContentType());
			finalMessage.setContent(multipartContent);
			finalMessage.saveChanges();
			
			out.close();
			byteArrayInputStream.close();
			
			// Send message
			Transport transport = session.getTransport(EMail.PROTOCAL.getValue());
			if (true) {
				transport.connect(EMail.SMTP_HOST.getValue(), EMail.USER_NAME.getValue(), EMail.PASSWORD.getValue());
			} else {
				transport.connect(); // javax.mail.AuthenticationFailedException
			}
			transport.sendMessage(finalMessage, finalMessage.getAllRecipients());
			transport.close();
			
			finalMessage.writeTo(System.out);
			finalMessage.writeTo(new FileOutputStream(EMail.SAVE_MESSAGE.getValue()));
		} else {
			message.writeTo(out);
		}
	}
	
	
	public static MimeBodyPart attachementBody(ClassFile attachment) throws Exception {
		// Per Attachment
		MimeBodyPart attachmentMimeBody = new MimeBodyPart();
		InputStream is = attachment.getStream();
		DataSource attachementDataSource = (DataSource) new ByteArrayDataSource(is, attachment.getContentType(),attachment.getFileName());
		attachmentMimeBody.setDataHandler(new DataHandler(attachementDataSource));
		attachmentMimeBody.setFileName(attachementDataSource.getName());
		
		//File fileFromStream = getFileFromStream(cerFileStream);
		//consoleLog("File : "+fileFromStream.getAbsolutePath());
		//DataSource source = new javax.activation.FileDataSource( fileFromStream );
		//fileBodyPart.setDataHandler( new DataHandler( source ) );
		//fileBodyPart.setFileName( fileFromStream.getName() );
		
		is.close();
		return attachmentMimeBody;
	}

	public static InputStream getCerFileStream(boolean isClassPath, String fileName) throws FileNotFoundException {
		InputStream stream = null;
		File file = new File(fileName);
		if (isClassPath) {
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			stream = classLoader.getResourceAsStream(fileName);
		} else {
			stream = new FileInputStream(file.getAbsolutePath());
		}
		consoleLog("File : "+ file.getAbsolutePath() +", Is ClassPath:"+ isClassPath);
		consoleLog("Stream: "+stream);
		return stream;
	}
	
	static  X509Certificate[] signerCertificatesChain;
	static X509Certificate x509Certificate;
	static SMIMESignedGenerator signer;
	static PrivateKey signerPrivateKey;
	public static void certificateGen(InputStream is, String password) throws Exception {
		MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
		mailcap.addMailcap(
				"application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		mailcap.addMailcap(
				"application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		mailcap.addMailcap(
				"application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		mailcap.addMailcap(
				"application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		mailcap.addMailcap(
				"multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
		CommandMap.setDefaultCommandMap(mailcap);

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		keystore.load(is, password.toCharArray());
			Enumeration<String> keyStoreAliasEnum = keystore.aliases();
			String aliasName = ElectronicMail.getAliasName(keystore);
			signerPrivateKey = (PrivateKey) keystore.getKey(aliasName, password.toCharArray());

		
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		Certificate certificate = keystore.getCertificate(aliasName);
		ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
		x509Certificate = (X509Certificate) cf.generateCertificate(bais);

		Certificate[] chain = (Certificate[]) keystore.getCertificateChain(aliasName);
			if (chain != null) {
				signerCertificatesChain = new X509Certificate[chain.length];
				for (int i = 0; i < chain.length; i++)
				{
					signerCertificatesChain[i] = (X509Certificate) chain[i];
				}
			}

		SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
		capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
		capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
		capabilities.addCapability(SMIMECapability.dES_CBC);

			ASN1EncodableVector attributes = new ASN1EncodableVector();
			attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
				SMIMEUtil.createIssuerAndSerialNumberFor(x509Certificate)));
			attributes.add(new SMIMECapabilitiesAttribute(capabilities));
		signer = new SMIMESignedGenerator();
		signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
					.setSignedAttributeGenerator(new AttributeTable(attributes))
					.build(x509Certificate.getSigAlgName(), signerPrivateKey, x509Certificate));
						
		List<X509Certificate> certList = Arrays.asList(signerCertificatesChain);
		Store certs = new JcaCertStore(certList);
		signer.addCertificates(certs);
	}
	
	private static MimeMessage getSingnedMessage(Enumeration headers, Object mimeObjectPart, String contentType) throws MessagingException {
		MimeMessage signedMessage = new MimeMessage(session);

		/** Set all original MIME headers in the signed message */
		while (headers.hasMoreElements()) {
			signedMessage.addHeaderLine((String) headers.nextElement());
		}

		signedMessage.setContent(mimeObjectPart, contentType);
		signedMessage.saveChanges();
		return signedMessage;
	}
	private static MimeBodyPart getEncryptedPart(MimeMessage message, String publicCerFile) 
			throws SMIMEException, CMSException, IllegalArgumentException, CertificateException, NoSuchProviderException, IOException {
		
		ASN1ObjectIdentifier encryptionOID = CMSAlgorithm.RC2_CBC;
		
		InputStream inputStream = getCerFileStream(false, publicCerFile);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate publicCer = (X509Certificate) certificateFactory.generateCertificate(inputStream);
		inputStream.close();
		
		SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
		// org.bouncycastle.cert.jcajce.JcaX509CertificateHolder.<init>(Unknown Source)
		// https://github.com/bcgit/bc-java/issues/310
		//encrypter.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(publicCer).setProvider("BC"));
		return encrypter.generate(message,
					new JceCMSContentEncryptorBuilder(encryptionOID, 40).setProvider("BC").build());
	}
	
}
class ByteArrayDataSource implements DataSource {
	private byte[] data; // data
	private String contentType; // content-type
	private String name; // name
	
	ByteArrayDataSource(InputStream inputdata, String contentType, String name) throws IOException {
		this.contentType = contentType;
		this.name = name;
		
		ByteArrayOutputStream internaldata = new ByteArrayOutputStream();
		copy(inputdata, internaldata);
		data = internaldata.toByteArray();
		internaldata.close();
	}
	
	public static void copy(InputStream in, OutputStream out) throws IOException {
		try {
			byte[] buffer = new byte[1024];
			int nrOfBytes = -1;
			while ((nrOfBytes = in.read(buffer)) != -1) {
				out.write(buffer, 0, nrOfBytes);
			}
			out.flush();
		} finally {
			try {
				in.close();
			} finally {
				out.close();
			}
		}
	}

	public String getContentType() {
		return contentType;
	}

	public InputStream getInputStream() throws IOException {
		return new ByteArrayInputStream(data);
	}

	public String getName() {
		return name;
	}

	public OutputStream getOutputStream() throws IOException {
		return null;
	}
}
class ClassFile {
	String fileName, contentType;
	InputStream stream;
	
	public String getFileName()
	{
		return fileName;
	}
	public String getContentType()
	{
		return contentType;
	}
	public InputStream getStream()
	{
		return stream;
	}
	public void setFileName(String fileName)
	{
		this.fileName = fileName;
	}
	public void setContentType(String contentType)
	{
		this.contentType = contentType;
	}
	public void setStream(InputStream stream)
	{
		this.stream = stream;
	}
}
/*
keytool -genkey -alias MyServer -keyalg RSA -validity 1825 -keystore "F:/MyServer.p12" -storetype pkcs12 -keypass password -storepass password -dname "CN=myserver.com,OU=My Company Name,O=My Organization,L=My Location,ST=My State,C=My Country Short Code"

> java.lang.SecurityException: class "org.bouncycastle.jcajce.provider.symmetric.IDEA$Mappings"'s signer information does not match signer information of other classes in the same package
using selenium-server-standalone? I had this problem until I got rid of this one.
https://github.com/lightbody/browsermob-proxy/issues/470


> java.io.IOException: PKCS12 key store mac invalid - wrong password or corrupted file. : Wrong Password

> com.sun.mail.smtp.SMTPSendFailedException: 530 5.7.0 Must issue a STARTTLS command first. q17sm9239202pfg.123 - gsmtp

530 5.7.0 Must issue a STARTTLS command first. g21sm9892457pfb.126 - gsmtp

if(transportProtocal.equalsIgnoreCase("SMTPS") || EMail.SMTP_PORT.getValue().equalsIgnoreCase("587")) {
	props.put("mail.transport.protocol", "smtps");
	props.put("mail.smtp.starttls.enable", "true");
}

> com.sun.mail.smtp.SMTPSendFailedException: 530-5.7.0 Authentication Required. Learn more at 530 5.7.0  https://support.google.com/mail/?p=WantAuthError u12sm6609805pgr.3 - gsmtp

IMAP: https://support.google.com/mail/answer/7126229?p=WantAuthError&visit_id=637168516138989254-1627005920&rd=2#cantsignin
POP: https://support.google.com/mail/answer/7104828
transport.connect(EMail.SMTP_HOST.getValue(), EMail.USER_NAME.getValue(), EMail.PASSWORD.getValue());

Control access to less secure apps: https://support.google.com/a/answer/6260879?hl=en
>> Less secure app access: https://myaccount.google.com/lesssecureapps
After diabiling we are getting > javax.mail.AuthenticationFailedException
*/
