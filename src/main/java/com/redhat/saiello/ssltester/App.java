package com.redhat.saiello.ssltester;

import org.apache.commons.cli.*;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;

/*
 based on https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java
 */
public class App
{


    /*
     * Enables logging of the SSLEngine operations.
     */
    private static boolean logging = false;


    static String serverKeyStoreFile;
    static String serverKeyStorePassphrase;

    static String serverTrustStoreFile;
    static String serverTrustStorePassphrase;

    static String clientKeyStoreFile;
    static String clientKeyStorePassphrase;

    static String clientTrustStoreFile;
    static String clientTrustStorePassphrase;

    private SSLEngine serverEngine;
    private ByteBuffer serverOut;       // write side of serverEngine
    private ByteBuffer serverIn;        // read side of serverEngine

    private SSLEngine clientEngine;
    private ByteBuffer clientOut;       // write side of clientEngine
    private ByteBuffer clientIn;        // read side of clientEngine

    /*
     * For data transport, this example uses local ByteBuffers.  This
     * isn't really useful, but the purpose of this example is to show
     * SSLEngine concepts, not how to do network transport.
     */
    private ByteBuffer cTOs;            // "reliable" transport client->server
    private ByteBuffer sTOc;            // "reliable" transport server->client

    public static void main(String args[]) throws Exception {

        Options options = new Options();

        options.addRequiredOption("sk", "serverKeystore", true, "Server Keystore");
        options.addRequiredOption("skp", "serverKeystorePassphrase", true, "Server Keystore Passphrase");

        options.addRequiredOption("st", "serverTruststore", true, "Server Truststore");
        options.addRequiredOption("stp","serverTruststorePassphrase", true, "Server Truststore Passphrase");

        options.addRequiredOption("ck", "clientKeystore", true, "Client Keystore");
        options.addRequiredOption("ckp", "clientKeystorePassphrase", true, "Client Keystore Passphrase");

        options.addRequiredOption("ct", "clientTruststore", true, "Client Truststore");
        options.addRequiredOption("ctp", "clientTruststorePassphrase", true, "Client Truststore Passphrase");

        options.addOption("print", "Enable logging");
        options.addOption("debug", "Enable ssl debug output");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try{
            cmd = parser.parse(options, args);
        }catch (ParseException e){
            e.printStackTrace();
            printUsage(options);
            System.exit(1);
            return;
        }


        serverKeyStoreFile = cmd.getOptionValue("serverKeystore");
        serverKeyStorePassphrase = cmd.getOptionValue("serverKeystorePassphrase");

        serverTrustStoreFile = cmd.getOptionValue("serverTruststore");
        serverTrustStorePassphrase = cmd.getOptionValue("serverTruststorePassphrase");

        clientKeyStoreFile = cmd.getOptionValue("clientKeystore");
        clientKeyStorePassphrase = cmd.getOptionValue("clientKeystorePassphrase");

        clientTrustStoreFile = cmd.getOptionValue("clientTruststore");
        clientTrustStorePassphrase = cmd.getOptionValue("clientTruststorePassphrase");

        if(cmd.hasOption("help")){
            printUsage(options);
        }

        if(cmd.hasOption("debug")){
            System.setProperty("javax.net.debug", "all");
        }

        if(cmd.hasOption("print")){
            logging = true;
        }

        new App().run();
    }

    private static void printUsage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar ssl-tester-1.0-SNAPSHOT-jar-with-dependencies.jar", options);
    }


    /*
     * Create and size the buffers appropriately.
     */
    private void createBuffers() {

        /*
         * We'll assume the buffer sizes are the same
         * between client and server.
         */
        SSLSession session = clientEngine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();

        log("AppBufferMax" + appBufferMax);
        log("NetBufferMax" + netBufferMax);
        /*
         * We'll make the input buffers a bit bigger than the max needed
         * size, so that unwrap()s following a successful data transfer
         * won't generate BUFFER_OVERFLOWS.
         *
         * We'll use a mix of direct and indirect ByteBuffers for
         * tutorial purposes only.  In reality, only use direct
         * ByteBuffers when they give a clear performance enhancement.
         */
        clientIn = ByteBuffer.allocate(appBufferMax + 50);
        serverIn = ByteBuffer.allocate(appBufferMax + 50);

        cTOs = ByteBuffer.allocateDirect(netBufferMax);
        sTOc = ByteBuffer.allocateDirect(netBufferMax);

        clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
    }


    private void run() throws Exception{
        boolean dataDone = false;

        createSSLEngines();
        createBuffers();

        SSLEngineResult clientResult;   // results from client's last operation
        SSLEngineResult serverResult;   // results from server's last operation

        /*
         * Examining the SSLEngineResults could be much more involved,
         * and may alter the overall flow of the application.
         *
         * For example, if we received a BUFFER_OVERFLOW when trying
         * to write to the output pipe, we could reallocate a larger
         * pipe, but instead we wait for the peer to drain it.
         */
        while (!isEngineClosed(clientEngine) ||
                !isEngineClosed(serverEngine)) {

            log("================");

            clientResult = clientEngine.wrap(clientOut, cTOs);
            log("client wrap: ", clientResult);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.wrap(serverOut, sTOc);
            log("server wrap: ", serverResult);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.flip();
            sTOc.flip();

            log("----");

            clientResult = clientEngine.unwrap(sTOc, clientIn);
            log("client unwrap: ", clientResult);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.unwrap(cTOs, serverIn);
            log("server unwrap: ", serverResult);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.compact();
            sTOc.compact();

            /*
             * After we've transfered all application data between the client
             * and server, we close the clientEngine's outbound stream.
             * This generates a close_notify handshake message, which the
             * server engine receives and responds by closing itself.
             *
             * In normal operation, each SSLEngine should call
             * closeOutbound().  To protect against truncation attacks,
             * SSLEngine.closeInbound() should be called whenever it has
             * determined that no more input data will ever be
             * available (say a closed input stream).
             */
            if (!dataDone && (clientOut.limit() == serverIn.position()) &&
                    (serverOut.limit() == clientIn.position())) {

                /*
                 * A sanity check to ensure we got what was sent.
                 */
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                log("\tClosing clientEngine's *OUTBOUND*...");
                clientEngine.closeOutbound();
                serverEngine.closeOutbound();
                dataDone = true;
                System.out.println("ok");
                System.exit(0);
            }
        }
    }

    private void createSSLEngines() throws Exception {
        // Server Engine
        serverEngine = createServerEngine();
        clientEngine = createClientEngine();
    }


    /*
     * If the result indicates that we have outstanding tasks to do,
     * go ahead and run them in this thread.
     */
    private static void runDelegatedTasks(SSLEngineResult result,
                                          SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                log("\trunning delegated task...");
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
            log("\tnew HandshakeStatus: " + hsStatus);
        }
    }


    private SSLEngine createServerEngine() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        ks.load(new FileInputStream(serverKeyStoreFile), serverKeyStorePassphrase.toCharArray());
        ts.load(new FileInputStream(serverTrustStoreFile), serverTrustStorePassphrase.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, serverKeyStorePassphrase.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLEngine sslServerEngine = sslCtx.createSSLEngine();
        sslServerEngine.setUseClientMode(false);
        sslServerEngine.setNeedClientAuth(true);

        return sslServerEngine;
    }

    private SSLEngine createClientEngine() throws Exception{
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        ks.load(new FileInputStream(clientKeyStoreFile), clientKeyStorePassphrase.toCharArray());
        ts.load(new FileInputStream(clientTrustStoreFile), clientTrustStorePassphrase.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, clientKeyStorePassphrase.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLEngine sslServerEngine = sslCtx.createSSLEngine("localhost", 80);
        sslServerEngine.setUseClientMode(true);

        return sslServerEngine;
    }


    private static boolean isEngineClosed(SSLEngine engine) {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    /*
     * Simple check to make sure everything came across as expected.
     */
    private static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            log("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    /*
     * Logging code
     */
    private static boolean resultOnce = true;

    private static void log(String str, SSLEngineResult result) {
        if (!logging) {
            return;
        }
        if (resultOnce) {
            resultOnce = false;
            System.out.println("The format of the SSLEngineResult is: \n" +
                    "\t\"getStatus() / getHandshakeStatus()\" +\n" +
                    "\t\"bytesConsumed() / bytesProduced()\"\n");
        }
        SSLEngineResult.HandshakeStatus hsStatus = result.getHandshakeStatus();
        log(str +
                result.getStatus() + "/" + hsStatus + ", " +
                result.bytesConsumed() + "/" + result.bytesProduced() +
                " bytes");
        if (hsStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            log("\t...ready for application data");
        }
    }

    private static void log(String str) {
        if (logging) {
            System.out.println(str);
        }
    }
}
