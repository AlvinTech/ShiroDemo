package shiro.chapter2.authenticator.strategy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.aerohive.core.data.jdbc.TransactionManagerNames;
import com.aerohive.core.logging.AHLogger;
import com.aerohive.core.logging.LoggerFactory;
import com.aerohive.core.service.annotation.TxMgr;
import com.aerohive.nms.config.certificate.auth.entry.ExtensionMapings;
import com.aerohive.nms.config.certificate.auth.enums.RevokeReason;
import com.aerohive.nms.config.certificate.auth.enums.UseType;
import com.aerohive.nms.config.certificate.auth.exception.CAException;
import com.aerohive.nms.config.certificate.auth.exception.CAException.Reason;
import com.aerohive.nms.config.certificate.auth.generators.CertificateGenerator;
import com.aerohive.nms.config.certificate.auth.parser.CertificateParser;
import com.aerohive.nms.data.cert.common.model.RootCA;
import com.aerohive.nms.data.cert.common.model.ServerCertificate;
import com.aerohive.nms.data.cert.common.repositories.ServerCertificateRepository;

/**
 * IMPORTANT: This is a generated source file, make sure you only add custom
 * implementation within BEGIN and END demarcated blocks. This ensures that your
 * custom code do not get overwritten during source code regeneration. There
 * MUST NOT be overlapping blocks
 * 
 * An example is as follows:
 * 
 * // CUSTOM_CODE 1 BEGIN ... ... ==> Here goes your implementation ... ... //
 * CUSTOM_CODE 1 END
 * 
 * NOTE: JAVA IMPORT LINES DO NOT NEED TO BE CONSIDERED.
 */
// CUSTOM_CODE_BLOCK 3 BEGIN
@Service("serverCertificateService")
@TxMgr(TransactionManagerNames.CERT_TX_MGR)
public class ServerCertificateServiceImpl implements ServerCertificateService {
    // CUSTOM_CODE_BLOCK 3 END
    // @Autowired
    // private VoDoUtil voDoUtil;

    @Autowired
    private ServerCertificateRepository rep;
    
    @Autowired
    private RootCAService rootService;

    private AHLogger       logger  = LoggerFactory.getLogger(ServerCertificateServiceImpl.class);
    
    private BigInteger getSerial()
    {
        //TODO: it should be auto increase.
        return BigInteger.probablePrime(64, new Random());
    }
    
    @Override
    public ServerCertificate generateServerSertificate(String commonName,Date validFrom,long period) throws CAException {
        int keySize = 2048;
        
            KeyPair keyPair;
            logger.info("start generate ServerCertificate.");
            try {
                keyPair = CertificateGenerator.getInstance().getKeyPair(keySize, "RSA", new SecureRandom());
                String subject = "CN="+commonName+",OU=Engineering,O=Aerohive Networks,C=US";
                ExtensionMapings map = ExtensionMapings.INSTANCE;
                List<Extension> extensions = new ArrayList<Extension>();
                RootCA signer = rootService.getLatestRootCA();
                
                //generate csr and subject
                PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(subject), keyPair.getPublic());
                JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
                ContentSigner contentSigner = csBuilder.build(keyPair.getPrivate());
                PKCS10CertificationRequest csr = p10Builder.build(contentSigner);
                X509Certificate signerCer = CertificateParser.analysisCert(new ByteArrayInputStream(signer.getCer()));
                PrivateKey privKey = CertificateParser.analysisKey(signer.getPrivateKey());
                BigInteger sn = getSerial();
                
                //add extensions
                extensions.add(new Extension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature)
                .getEncoded()));
                extensions.add(new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage( KeyPurposeId.id_kp_serverAuth).getEncoded()));
                extensions.add(new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));
                extensions.add(new Extension(Extension.subjectKeyIdentifier,false,new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerCer.getPublicKey()).getEncoded()));
                extensions.add(new Extension(Extension.authorityKeyIdentifier,false,new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCer.getPublicKey()).getEncoded()));
                //sign
                X509Certificate signResult = CertificateGenerator.getInstance().signPKCS10(csr.getEncoded(), signerCer, sn, validFrom, period, privKey, extensions);
                
                //set value to return 
                ServerCertificate cer = new ServerCertificate();
                cer.setCer(signResult.getEncoded());
                cer.setCreateDate(new Date());
                cer.setServerCN(commonName);
                cer.setRevokeReason(RevokeReason.UNREVOKE.getReason());
                cer.setRootCaId(signer.getId());
                cer.setSerialNumber(sn.toString());
                cer.setUseType(UseType.IDM.getUseType());
                cer.setValidFrom(validFrom);
                cer.setValidTo(new Date(validFrom.getTime()+period));
                cer.setPrivateKey(keyPair.getPrivate().getEncoded());
                logger.info("Generate ServerCertificate successfully.");
                return cer;
            } catch (NoSuchAlgorithmException e) {
                logger.error("No such algorithm when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "No such algorithm.");
            }catch ( NoSuchProviderException e) {
                logger.error("No such Provider when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "No such Provider.");
            } catch (OperatorCreationException e) {
                logger.error("The operator not supported when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "OperatorCreationException.");
            } catch (CertificateException e) {
                logger.error("Certificate Can't be resolved when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "CertificateException");
            } catch (InvalidKeySpecException e) {
                logger.error("Root Private Key Can't be found by this spec name when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "InvalidKeySpecException");
            } catch (IOException e) {
                logger.error("IO Exception when get root certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "IOException");
            } catch (InvalidKeyException e) {
                logger.error("Root Private Key Can't be resolved when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "InvalidKeyException");
            } catch (PKCSException e) {
                logger.error("CSR Can't be resolved when generate server certificate.",e);
                throw new CAException(Reason.SIGN_ERROR, "PKCSException");
            } 

    }

    @Override
    public List<ServerCertificate> getServerCertificateByCommonName(String commonName) {
        return rep.findByServerCN(commonName);
    }

    
    
    public static X509Certificate test(String commonName,Date validFrom,long period) throws CAException {
        int keySize = 2048;
            System.out.println(new Date().getTime());
            KeyPair keyPair;
            try {
                keyPair = CertificateGenerator.getInstance().getKeyPair(keySize, "RSA", new SecureRandom());
                String subject = "CN="+commonName+",OU=Engineering,O=Aerohive Networks,C=US";
                ExtensionMapings map = ExtensionMapings.INSTANCE;
                List<Extension> extensions = new ArrayList<Extension>();
                
                //generate csr and subject
                PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(subject), keyPair.getPublic());
                JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
                ContentSigner contentSigner = csBuilder.build(keyPair.getPrivate());
                PKCS10CertificationRequest csr = p10Builder.build(contentSigner);
                BigInteger sn = new BigInteger("123456");
                PrivateKey privateKey = initPrivateKey();
                X509Certificate cert = readCertificate();
                PublicKey publicKey = cert.getPublicKey();
                //add extensions
//                extensions.add(new Extension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature)
//                .getEncoded()));
//                extensions.add(new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage( KeyPurposeId.id_kp_serverAuth).getEncoded()));
//                extensions.add(new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));
//                extensions.add(new Extension(Extension.authorityKeyIdentifier,false,new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(publicKey).getEncoded()));
                //sign
                System.out.println(new Date().getTime());
                Date d1= new Date();
                X509Certificate signResult = CertificateGenerator.getInstance().signPKCS10(csr.getEncoded(), cert, sn, validFrom, period, privateKey, extensions);
                Date d2= new Date();
                System.out.println(new Date().getTime());
                System.out.println(d2.getTime()-d1.getTime());
                return signResult; 
                //set value to return 
            } catch (NoSuchAlgorithmException e) {
                throw new CAException(Reason.SIGN_ERROR, "No such algorithm.");
            }catch ( NoSuchProviderException e) {
                throw new CAException(Reason.SIGN_ERROR, "No such Provider.");
            } catch (OperatorCreationException e) {
                throw new CAException(Reason.SIGN_ERROR, "OperatorCreationException.");
            } catch (CertificateException e) {
                throw new CAException(Reason.SIGN_ERROR, "CertificateException");
            } catch (IOException e) {
                throw new CAException(Reason.SIGN_ERROR, "IOException");
            } catch (InvalidKeyException e) {
                throw new CAException(Reason.SIGN_ERROR, "InvalidKeyException");
            } catch (PKCSException e) {
                throw new CAException(Reason.SIGN_ERROR, "PKCSException");
            }

    }
    private static PrivateKey initPrivateKey() {  
        try {  
            
            BufferedReader br = new BufferedReader(new FileReader("/root/subca.key"));  
            String s = br.readLine();  
            StringBuffer privatekey = new StringBuffer();  
            s = br.readLine();  
            while (s.charAt(0) != '-') {  
                privatekey.append(s + "\r");  
                s = br.readLine();  
            }  
            
            Base64 b64 =new Base64();
            byte[] keybyte=b64.decode(privatekey.toString());
              
            KeyFactory kf = KeyFactory.getInstance("RSA");  
              
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybyte);  
              
            return kf.generatePrivate(keySpec);  
        } catch (Exception e) {  
            e.printStackTrace();  
            return null;
        }  
          
    }  
    
   
    
    private static X509Certificate readCertificate() {  
        try {  
            BufferedReader br = new BufferedReader(new FileReader("/root/subca.pem"));    
            String s = br.readLine();  
            StringBuffer publickey = new StringBuffer();  
              
            Base64 b64 =new Base64();
            byte[] keybyte=b64.decode(publickey.toString());
            CertificateFactory cetFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cetFactory.generateCertificate(new FileInputStream(new File("/root/subca.pem")));
            return cert;  
        } catch (Exception e) {  
            return null;
        }  
    }  
    
    public static void main(String args[])
    {
        
        test("AeroHive",new Date(),100000l);
    }
}
