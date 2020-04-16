///$Header: /as2/de/mendelson/comm/as2/integration/sample/AS2MessageReceiver1.java 23    7.11.18 10:39 Heller $
package de.mendelson.comm.as2.integration.sample;

/*
 * Copyright (C) mendelson-e-commerce GmbH Berlin Germany
 *
 * This software is subject to the license agreement set forth in the license.
 * Please read and agree to all terms before using this software.
 * Other product and brand names are trademarks of their respective owners.
 */
/**
 * This is a sample servlet to receive AS2 messages. Deploy this in any web
 * container to receive and process. The sample will receive the message,
 * extract its playload, verify its signature, decrypt it and then send a
 * sync/async MDN in failure or processed state. AS2 messages. The receipt data
 * is stored in a file called "AS2MessageReceiver_data.payload" if no filename
 * has been transfered. Else the transfered filename is used
 *
 * @author S.Heller
 * @version $Revision: 23 $
 */

import de.mendelson.comm.as2.AS2Exception;
import de.mendelson.comm.as2.integration.APIVersion;
import de.mendelson.comm.as2.integration.AS2AsyncMDNSender;
import de.mendelson.comm.as2.integration.AS2IntegrationConstants;
import de.mendelson.comm.as2.integration.AS2MDNBuilder;
import de.mendelson.comm.as2.integration.AS2MessageAnalyzer;
import de.mendelson.comm.as2.integration.AS2MessageExtraction;
import de.mendelson.comm.as2.integration.KeystoreInformation;
import de.mendelson.comm.as2.integration.data.AS2HTTPData;
import de.mendelson.comm.as2.integration.data.AS2PayloadData;
import de.mendelson.comm.as2.integration.data.AS2RemoteHTTPData;
import de.mendelson.util.security.BCCryptoHelper;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

@RestController
@RequestMapping("/as2/HttpReceiver")
public class AS2MessageReceiver1 {

    //Logger, its also possible to extend it for database logging etc
    private final Logger logger = Logger.getAnonymousLogger();

    public AS2MessageReceiver1() {
        // performs "Security.addProvider(new BouncyCastleProvider());" and adds some BC related system properties
        new BCCryptoHelper().initialize();
    }

    /**
     * A GET request should be rejected
     */
//    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        PrintWriter out = res.getWriter();
        res.setContentType("text/html");
        out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">");
        out.println("<html>");
        out.println("<head>");
        out.println("<title>A2MessageReceiver sample 1</title>");
        out.println("</head>");
        out.println("<body>");
        out.println("<H2>A2MessageReceiver sample servlet 1</H2>");
        out.println("<BR>This sample uses the mendelson AS2 API " + APIVersion.getVersion() + "<BR><BR>");
        out.println("<BR><br>You have performed an HTTP GET on this URL. <BR>");
        out.println("To submit an AS2 message, you must POST the it to this URL <BR>");
        out.println("</body>");
        out.println("</html>");
    }

    /**
     * POST by the HTTP client: receive the AS2 message and work on it
     */
//    @Override
    @PostMapping()
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        StringBuilder mdnText = new StringBuilder();
        //instanciate the message analyzer
        AS2MessageAnalyzer analyzer = null;
        try {
            InputStream inStream = request.getInputStream();
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            this.copyStreams(inStream, byteOut);
            byteOut.flush();
            byteOut.close();
            byte[] rawData = byteOut.toByteArray();
            //extract header
            Properties header = new Properties();
            Enumeration enumeration = request.getHeaderNames();
            while (enumeration.hasMoreElements()) {
                String key = (String) enumeration.nextElement();
                header.setProperty(key.toLowerCase(), request.getHeader(key));
            }
            //analyze the message
            analyzer = new AS2MessageAnalyzer(header, rawData);
            //This is a small sample that shows on how to generate exceptions to generate
            //an MDN of them later:
            //  AS2Exception unknownTradingPartnerException = AS2ExceptionFactory.generateException(
            //         analyzer, AS2ExceptionFactory.UNKNOWN_TRADING_PARTNER_ERROR,
            //         "The trading partner " + analyzer.getSenderAS2Id() + " is unknown.");
            //  throw (unknownTradingPartnerException);
            //the analyzer provides key data for the processing now. We will extract the payload
            //now
            //instanciate the extraction
            AS2MessageExtraction extraction = new AS2MessageExtraction(this.logger);
            //define the certificate information
            //signature information. The certificates and keys are stored in keystores
            KeystoreInformation signatureInfo = new KeystoreInformation();
            signatureInfo.setKeystoreFilename("certificates.p12");
            signatureInfo.setPassword("test".toCharArray());
            signatureInfo.setType(AS2IntegrationConstants.KEYSTORE_TYPE_PKCS12);
            //the signature of inbound messages is verified using the senders certificate
            //lets say in this sample that the message sender has signed his message using the key "key1".
            extraction.setSignature(signatureInfo, "Key3");

            //encryption information The certificates and keys are stored in keystores
            KeystoreInformation encryptionInfo = new KeystoreInformation();
            encryptionInfo.setKeystoreFilename("certificates.p12");
            encryptionInfo.setPassword("test".toCharArray());
            encryptionInfo.setType(AS2IntegrationConstants.KEYSTORE_TYPE_PKCS12);
            //the decryption of inbound AS2 messages is performed using the receivers key
            //Lets say in this sample that the receiver decrypts his messages using the key "key1".
            extraction.setEncryption(signatureInfo, "Key3");

            //get the AS2 payload, this could be stores somewhere or send to the next processing
            //system. The signature is verified
            boolean ignoreSignatureVarificationError = false;
            String contentTransferEncoding = null;
            List<AS2PayloadData> payloadList = extraction.extractPayloads(header, rawData, contentTransferEncoding, ignoreSignatureVarificationError);
            for (int i = 0; i < payloadList.size(); i++) {
                AS2PayloadData payload = payloadList.get(i);
                //store the received payload in a file called "AS2MessageReceiver_data.payload" if no
                //filename has been transmissed            
                Path outFile = null;
                if (payload.getOriginalFilename() != null) {
                    outFile = Paths.get(payload.getOriginalFilename());
                } else {
                    outFile = Paths.get("AS2MessageReceiver_data_" + i + ".payload");
                }
                OutputStream payloadOutStream = null;
                try {
                    payloadOutStream = Files.newOutputStream(outFile);
                    ByteArrayInputStream byteInStream = new ByteArrayInputStream(payload.getData());
                    this.copyStreams(byteInStream, payloadOutStream);
                    inStream.close();
                } finally {
                    payloadOutStream.flush();
                    payloadOutStream.close();
                }
                //write some information about the signature/encryption that has been used:
                this.logger.info("The payload has been extracted to " + outFile.toAbsolutePath().toString() + ".");
                mdnText.append("The payload has been extracted to " + outFile.toAbsolutePath().toString() + ".\n");
            }
            this.logger.info("Used encryption: " + (payloadList.get(0).getEncryptionAlgorithm()==null?"None":payloadList.get(0).getEncryptionAlgorithm()));
            mdnText.append("Used encryption: " + (payloadList.get(0).getEncryptionAlgorithm()==null?"None":payloadList.get(0).getEncryptionAlgorithm()) + "\n" );
            this.logger.info("Used signature: " + payloadList.get(0).getSignatureAlgorithm());
            mdnText.append("Used signature: " + payloadList.get(0).getSignatureAlgorithm() + "\n");
            this.logger.info("Used compression: " + (payloadList.get(0).getCompression() == AS2IntegrationConstants.COMPRESSION_NONE ? "None" : "ZLIB"));
            mdnText.append("Used compression: " + (payloadList.get(0).getCompression() == AS2IntegrationConstants.COMPRESSION_NONE ? "None" : "ZLIB") + "\n");
            if (analyzer.requestAsyncMDN()) {
                //send a async MDN on a new connection
                this.sendAsyncMDNOk(analyzer, payloadList.get(0).getMIC(), mdnText.toString());
            } else {
                //send a sync MDN on the same connection
                this.sendSyncMDNOk(response, analyzer, payloadList.get(0).getMIC(), mdnText.toString());
            }
            //return HTTP 200
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (AS2Exception e) {
            logger.log(Level.ALL, e.getMessage(), e );
            try {
                //something went wrong: send MDN
                if (analyzer.requestAsyncMDN()) {
                    //send an async MDN on a new connection
                    this.sendAsyncMDNFailure(e, analyzer);
                } else {
                    //send a sync MDN on the inbound http connection
                    this.sendSyncMDNFailure(e, response, analyzer);
                }
            } catch (Throwable ex) {
                ex.printStackTrace();
                //return HTTP 500, this is an internal server error
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        } catch (Throwable e) {
            logger.log(Level.ALL, e.getMessage(), e );
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            //return HTTP 500, this is an internal server error
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        stringWriter.toString());
            } catch (Exception ex) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }
    }//end of doPost

    /**
     * Send a sync MDN, everything is ok. The MDN is sent on the inbound HTTP
     * connection
     */
    private void sendSyncMDNOk(HttpServletResponse response, AS2MessageAnalyzer analyzer, String computedMIC, String mdnText) throws Exception {
        AS2MDNBuilder builder = new AS2MDNBuilder(analyzer);
        builder.setLogger(this.logger);
        //set the human readable MDN details. Mainly they are ignored by the receiver because they
        //do only contain additional information
        builder.setDetails("The AS2 message has been received by the A2MessageReceiver sample 1 - API " + APIVersion.getVersion()
                + "\n" + mdnText);
        //signature information. The certificates and keys are stored in keystores
        KeystoreInformation signatureInfo = new KeystoreInformation();
        signatureInfo.setKeystoreFilename("certificates.p12");
        signatureInfo.setPassword("test".toCharArray());
        signatureInfo.setType(AS2IntegrationConstants.KEYSTORE_TYPE_PKCS12);
        builder.setSignature(signatureInfo, "Key3", AS2IntegrationConstants.SIGNATURE_SHA1);
        builder.setMIC(computedMIC);
        //Now build the MDN and pass its values to the servlet response
        AS2HTTPData mdn = builder.createMDNOk();
        //set response header
        Iterator iterator = mdn.getHeader().keySet().iterator();
        while (iterator.hasNext()) {
            String key = (String) iterator.next();
            response.setHeader(key, mdn.getHeader().getProperty(key));
        }
        //set response body
        ByteArrayInputStream inStream = new ByteArrayInputStream(mdn.getData());
        this.copyStreams(inStream, response.getOutputStream());
        inStream.close();
        response.getOutputStream().flush();
    }

    /**
     * Send a sync MDN, a problem occured. The MDN is sent on the inbound HTTP
     * connection
     */
    private void sendSyncMDNFailure(AS2Exception exception, HttpServletResponse response, AS2MessageAnalyzer analyzer) throws Exception {
        AS2MDNBuilder builder = new AS2MDNBuilder(analyzer);
        builder.setLogger(this.logger);
        //signature information. The certificates and keys are stored in keystores
        KeystoreInformation signatureInfo = new KeystoreInformation();
        signatureInfo.setKeystoreFilename("certificates.p12");
        signatureInfo.setPassword("test".toCharArray());
        signatureInfo.setType(AS2IntegrationConstants.KEYSTORE_TYPE_PKCS12);
        builder.setSignature(signatureInfo, "Key3", AS2IntegrationConstants.SIGNATURE_SHA1);
        //Now build the MDN and pass its values to the servlet response
        AS2HTTPData mdn = builder.createMDNFailure(exception);
        //set response header
        Iterator iterator = mdn.getHeader().keySet().iterator();
        while (iterator.hasNext()) {
            String key = (String) iterator.next();
            response.setHeader(key, mdn.getHeader().getProperty(key));
        }
        //set response body
        ByteArrayInputStream inStream = new ByteArrayInputStream(mdn.getData());
        this.copyStreams(inStream, response.getOutputStream());
        inStream.close();
        response.getOutputStream().flush();
    }

    /**
     * Send an async MDN on a new connection, everything is ok
     */
    private void sendAsyncMDNOk(final AS2MessageAnalyzer analyzer, final String computedMIC, final String mdnText) throws Exception {
        Runnable runnable = new Runnable() {

            @Override
            public void run() {
                try {
                    //wait 5s to let the inbound connection to be closed before a new outbound is established
                    Thread.sleep(TimeUnit.SECONDS.toMillis(5));
                    AS2MDNBuilder builder = new AS2MDNBuilder(analyzer);
                    builder.setLogger(logger);
                    //set the human readable MDN deftails. Mainly they are ignored by the receiver because they
                    //do only contain additional information
                    builder.setDetails("The AS2 message has been received by the A2MessageReceiver sample 1 - API " + APIVersion.getVersion()
                            + "\n" + mdnText);
                    //signature information. The certificates and keys are stored in keystores
                    KeystoreInformation signatureInfo = new KeystoreInformation();
                    signatureInfo.setKeystoreFilename("certificates.p12");
                    signatureInfo.setPassword("test".toCharArray());
                    signatureInfo.setType(AS2IntegrationConstants.KEYSTORE_TYPE_PKCS12);
                    builder.setSignature(signatureInfo, "Key3", AS2IntegrationConstants.SIGNATURE_SHA1);
                    builder.setMIC(computedMIC);
                    //Now build the MDN and pass its values to the servlet response
                    AS2HTTPData mdn = builder.createMDNOk();
                    AS2AsyncMDNSender sender = new AS2AsyncMDNSender(builder);
                    sender.setLogger(logger);
                    sender.setURL(analyzer.getAsyncMDNURL());
                    AS2RemoteHTTPData response = sender.send(mdn.getHeader(), mdn.getData());
                } catch (Throwable e) {
                    logger.severe(e.getClass().getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
        Executors.newSingleThreadExecutor().submit(runnable);
    }

    /**
     * Send an async MDN on a new connection, a problem occured
     */
    private void sendAsyncMDNFailure(final AS2Exception exception, final AS2MessageAnalyzer analyzer) {
        Runnable runnable = new Runnable() {

            @Override
            public void run() {
                try {
                    Thread.sleep(TimeUnit.SECONDS.toMillis(5));
                    AS2MDNBuilder builder = new AS2MDNBuilder(analyzer);
                    builder.setLogger(logger);
                    //set the human readable MDN deftails. Mainly they are ignored by the receiver because they
                    //do only contain additional information
                    builder.setDetails("The AS2 message has been received by the A2MessageReceiver sample 1 - API " + APIVersion.getVersion());
                    //signature information. The certificates and keys are stored in keystores
                    KeystoreInformation signatureInfo = new KeystoreInformation();
                    signatureInfo.setKeystoreFilename("certificates.p12");
                    signatureInfo.setPassword("test".toCharArray());
                    signatureInfo.setType(AS2IntegrationConstants.KEYSTORE_TYPE_PKCS12);
                    builder.setSignature(signatureInfo, "Key3", AS2IntegrationConstants.SIGNATURE_SHA1);
                    //Now build the MDN and pass its values to the servlet response
                    AS2HTTPData mdn = builder.createMDNFailure(exception);
                    AS2AsyncMDNSender sender = new AS2AsyncMDNSender(builder);
                    sender.setLogger(logger);
                    sender.setURL(analyzer.getAsyncMDNURL());
                    AS2RemoteHTTPData response = sender.send(mdn.getHeader(), mdn.getData());
                } catch (Throwable e) {
                    logger.severe(e.getClass().getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
        Executors.newSingleThreadExecutor().submit(runnable);
    }

    /**
     * Copies all data from one stream to another
     */
    private void copyStreams(InputStream in, OutputStream out)
            throws IOException {
        BufferedInputStream inStream = new BufferedInputStream(in);
        BufferedOutputStream outStream = new BufferedOutputStream(out);
        //copy the contents to an output stream
        byte[] buffer = new byte[1024];
        int read = 1024;
        //a read of 0 must be allowed, sometimes it takes time to
        //extract data from the input
        while (read != -1) {
            read = inStream.read(buffer);
            if (read > 0) {
                outStream.write(buffer, 0, read);
            }
        }
        outStream.flush();
    }

//    @Override
    public String getServletInfo() {
        return "A2MessageReceiver sample 1 - API " + APIVersion.getVersion();
    }
}

