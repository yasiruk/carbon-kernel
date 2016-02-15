/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.jaas.modules;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.multipart.Attribute;
import io.netty.handler.codec.http.multipart.DefaultHttpDataFactory;
import io.netty.handler.codec.http.multipart.HttpPostRequestDecoder;
import io.netty.handler.codec.http.multipart.InterfaceHttpData;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.security.exception.CarbonSecurityException;
import org.wso2.carbon.security.jaas.CarbonCallback;
import org.wso2.carbon.security.jaas.CarbonPrincipal;
import org.xml.sax.SAXException;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;


/**
 * JAAS LoginModule that verifies a SAML response from an IdP.
 */
public class SAMLLoginModule implements LoginModule {

    private static final Logger log = LoggerFactory.getLogger(SAMLLoginModule.class);
    //string constants used as parameters in the options passed to the loginModule
    public static final String OPT_KEYSTORE_FILE = "keystorefile";
    public static final String OPT_IDP_CERT_ALIAS = "certalias";
    public static final String OPT_KEYSTORE_PW = "keystorepassword";

    private static Map<String, KeyStore> keystoreCache = new HashMap<>();

    //details of the keystore, populated with default entries.
    private String keyStoreFile = "wso2carbon.jks";
    private String certificateAlias = "wso2carbon";
    private String keyStorePassword = "wso2carbon";
    private String b64SAMLResponse;
    private Response samlResponse;
    private CarbonPrincipal userPrincipal;
    private KeyStore keyStore;
    boolean success;
    private Subject subject;
    private CallbackHandler callbackHandler;

    private Map<String, ?> options;


    /**
     * @param subject         The <code>Subject</code> instance that needs to be authenticated
     * @param callbackHandler Expects a <code>CarbonCallBackHandler</code> instance
     * @param sharedState     This module does not use any parameters from shared state
     * @param options         If all three are provided, uses the options "keystorefile", "keystorealias",
     *                        "keystorepassword" to override the
     *                        default keystore.
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.options = options;
        //shared state is ignored as it is note used.

        if (options != null && options.containsKey(OPT_KEYSTORE_FILE) && options.containsKey(OPT_IDP_CERT_ALIAS)
                && options.containsKey(OPT_KEYSTORE_PW)) {
            keyStoreFile = (String) options.get(OPT_KEYSTORE_FILE);
            certificateAlias = (String) options.get(OPT_IDP_CERT_ALIAS);
            keyStorePassword = (String) options.get(OPT_KEYSTORE_PW);
        }

        this.success = false;

    }

    @Override
    public boolean login() throws LoginException {
        CarbonCallback<String> samlCallback = new CarbonCallback<>(CarbonCallback.Type.SAML);
        Callback[] callbacks = {samlCallback};

        try {
            callbackHandler.handle(callbacks);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException("Failed fetch SAML data");
        }
        Assertion assertion = (Assertion) ((CarbonCallback)callbacks[0]).getContent();

        try {
            validateSignature(assertion);
        } catch (ValidationException e) {
            throw new LoginException("Failed to validate SAML Signature");
        }
        if (samlResponse.getAssertions().size() > 0) { //assertions exist and are not encrypted
            org.opensaml.saml2.core.Subject samlSubject =assertion.getSubject();
            if (samlSubject != null && samlSubject.getNameID().getValue() != null) {
                success = true;
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        userPrincipal = new CarbonPrincipal(samlResponse.getAssertions().get(0).getSubject().getNameID().getValue());
        subject.getPrincipals().add(userPrincipal);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        success = false;
        subject.getPrincipals().remove(userPrincipal);
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        success = false;
        subject.getPrincipals().remove(userPrincipal);
        return true;
    }

    private void validateSignature(Assertion samlAssertion) throws ValidationException {
        if (samlAssertion == null) {
            throw new ValidationException("Validation Failed");
        }

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        try {
            //validate the saml profile of the response
            profileValidator.validate(samlAssertion.getSignature());
            Credential verificationCredential = getVerificationCredential();
            SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
            //validate the signature of the response
            sigValidator.validate(samlAssertion.getSignature());
        } catch (Exception e) {
            throw new ValidationException("Validation Failed", e);
        }
    }


    /**
     * <p>
     * This method retrieves the certificate from the keystore
     * </p>
     *
     * @return
     * @throws Exception
     */
    private Credential getVerificationCredential() throws CarbonSecurityException {
        BasicX509Credential basicX509Credential = new BasicX509Credential();
        if (keyStore == null) {
            keyStore = getKeystore(keyStoreFile, keyStorePassword.toCharArray());
        }

        try {
            basicX509Credential.setEntityCertificate((X509Certificate) keyStore.getCertificate(certificateAlias));
            basicX509Credential.setPublicKey(keyStore.getCertificate(certificateAlias).getPublicKey());
        } catch (KeyStoreException e) {
            throw new CarbonSecurityException("Failed to fetch certificate '" + certificateAlias + "' from keystore '"
                    + keyStoreFile + "'", e);
        }

        return basicX509Credential;

    }

    private void requestPreProcessor(HttpRequest request) throws CarbonSecurityException {
        HttpPostRequestDecoder decoder = new HttpPostRequestDecoder(new DefaultHttpDataFactory(false), request);

        InterfaceHttpData data = decoder.getBodyHttpData("SAMLResponse");
        if (data.getHttpDataType() == InterfaceHttpData.HttpDataType.Attribute) {
            Attribute attribute = (Attribute) data;

            try {
                this.b64SAMLResponse = attribute.getValue();
            } catch (IOException e) {
                throw new CarbonSecurityException("Error while reading SAML2 Response", e);
            }

        } else {
            throw new CarbonSecurityException("SAML2 Response not found");
        }
    }

    private Response parseSAMLResponse(String b64SAMLResponse) throws LoginException {
        XMLObject xmlObj = null;
        try {
            String responseXml;
            responseXml = new String(Base64.decode(b64SAMLResponse), "UTF-8");
            DefaultBootstrap.bootstrap();

            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            ByteArrayInputStream is = new ByteArrayInputStream(responseXml.getBytes("UTF8"));
            Document document = docBuilder.parse(is);
            is.close();
            Element element = document.getDocumentElement();

            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

            xmlObj = unmarshaller.unmarshall(element);

        } catch (UnsupportedEncodingException e) {
            throw new LoginException("Error decoding SAML Response");
        } catch (ConfigurationException e) {
            throw new LoginException("Failed bootstrapping opensaml");
        } catch (ParserConfigurationException | SAXException | IOException | UnmarshallingException e) {
            throw new LoginException("Failed to parse SAML XML Response");
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.error("Error while passing SAML Reponse", e);
            }
        }
        return (Response) xmlObj;
    }

    private static KeyStore getKeystore(String keyStorePath, char[] keyStorePassword) throws CarbonSecurityException {
        KeyStore keyStore = null;

        if(keystoreCache.containsKey(keyStorePath))
            return keystoreCache.get(keyStorePath);

        try {
            keyStore = KeyStore.getInstance("jks");
            FileInputStream fileInputStream = new FileInputStream(keyStorePath);
            keyStore.load(fileInputStream, keyStorePassword);

            fileInputStream.close();

            keystoreCache.put(keyStorePath, keyStore);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new CarbonSecurityException("Failed to load keystore '" + keyStorePath + "'", e);
        }
        return keyStore;
    }
}
