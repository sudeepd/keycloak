package org.keycloak.protocol.saml;

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.saml.common.constants.GeneralConstants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

import static org.keycloak.protocol.saml.DefaultSamlArtifactResolverFactory.TYPE_CODE;

/**
 * ArtifactResolver for artifact-04 format.
 * Other kind of format for artifact are allowed by standard but not specified.
 * Artifact 04 is the only one specified in SAML2.0 specification.
 */
public class DefaultSamlArtifactResolver implements ArtifactResolver {
    private int ARTIFACT_LENGTH = 0;
    private String DIGEST_ALGORITHM = "";
    private int HASH_SIZE_IN_BYTES = 0;

    public DefaultSamlArtifactResolver() {
        ARTIFACT_LENGTH = CryptoServicesRegistrar.isInApprovedOnlyMode() ? 56 : 44;
        DIGEST_ALGORITHM = CryptoServicesRegistrar.isInApprovedOnlyMode() ? "SHA-256" : "SHA-1";
        HASH_SIZE_IN_BYTES = CryptoServicesRegistrar.isInApprovedOnlyMode() ? 32 : 20;
    }
    protected static final Logger logger = Logger.getLogger(SamlService.class);

    @Override
    public String resolveArtifact(AuthenticatedClientSessionModel clientSessionModel, String artifact) throws ArtifactResolverProcessingException {
        String artifactResponseString = clientSessionModel.getNote(GeneralConstants.SAML_ARTIFACT_KEY + "=" + artifact);
        clientSessionModel.removeNote(GeneralConstants.SAML_ARTIFACT_KEY + "=" + artifact);

        logger.tracef("Artifact response for artifact %s, is %s", artifact, artifactResponseString);

        if (Strings.isNullOrEmpty(artifactResponseString)) {
            throw new ArtifactResolverProcessingException("Artifact not present in ClientSession.");
        }

        return artifactResponseString;
    }

    @Override
    public ClientModel selectSourceClient(String artifact, Stream<ClientModel> clients) throws ArtifactResolverProcessingException {
        try {
            byte[] source = extractSourceFromArtifact(artifact);

            MessageDigest digester = MessageDigest.getInstance(DIGEST_ALGORITHM);
            return clients.filter(clientModel -> Arrays.equals(source,
                    digester.digest(clientModel.getClientId().getBytes(Charsets.UTF_8))))
                    .findFirst()
                    .orElseThrow(() -> new ArtifactResolverProcessingException("No client matching the artifact source found"));
        } catch (NoSuchAlgorithmException e) {
            throw new ArtifactResolverProcessingException(e);
        }
    }

    @Override
    public String buildArtifact(AuthenticatedClientSessionModel clientSessionModel, String entityId, String artifactResponse) throws ArtifactResolverProcessingException {
        String artifact = createArtifact(entityId);

        clientSessionModel.setNote(GeneralConstants.SAML_ARTIFACT_KEY + "=" + artifact, artifactResponse);

        return artifact;
    }

    private void assertSupportedArtifactFormat(String artifactString) throws ArtifactResolverProcessingException {
        byte[] artifact = Base64.getDecoder().decode(artifactString);
        // In fips mode, the length of artifact will be 56 because of sha2

        if (artifact.length != ARTIFACT_LENGTH) {
            throw new ArtifactResolverProcessingException("Artifact " + artifactString + " has a length of " + artifact.length + ". It should be " + ARTIFACT_LENGTH);
        }
        if (artifact[0] != TYPE_CODE[0] || artifact[1] != TYPE_CODE[1]) {
            throw new ArtifactResolverProcessingException("Artifact " + artifactString + " does not start with 0x0004");
        }
    }

    private byte[] extractSourceFromArtifact(String artifactString) throws ArtifactResolverProcessingException {
        assertSupportedArtifactFormat(artifactString);

        byte[] artifact = Base64.getDecoder().decode(artifactString);

        // number of bytes depends on FIPS vs non fips
        byte[] source = new byte[HASH_SIZE_IN_BYTES];
        System.arraycopy(artifact, 4, source, 0, source.length);

        return source;
    }

    /**
     * Creates an artifact. Format is:
     * <p>
     * SAML_artifact := B64(TypeCode EndpointIndex RemainingArtifact)
     * <p>
     * TypeCode := 0x0004
     * EndpointIndex := Byte1Byte2
     * RemainingArtifact := SourceID MessageHandle
     * <p>
     * SourceID := 20-byte_sequence, used by the artifact receiver to determine artifact issuer
     * MessageHandle := 20-byte_sequence
     *
     * @param entityId the entity id to encode in the sourceId
     * @return an artifact
     * @throws ArtifactResolverProcessingException
     */
    public String createArtifact(String entityId) throws ArtifactResolverProcessingException {
        try {
            SecureRandom handleGenerator = SecureRandom.getInstance("DEFAULT");
            byte[] trimmedIndex = new byte[2];

            MessageDigest digester = MessageDigest.getInstance(DIGEST_ALGORITHM);
            byte[] source = digester.digest(entityId.getBytes(Charsets.UTF_8));

            byte[] assertionHandle = new byte[20];
            handleGenerator.nextBytes(assertionHandle);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(TYPE_CODE);
            bos.write(trimmedIndex);
            bos.write(source);
            bos.write(assertionHandle);

            byte[] artifact = bos.toByteArray();

            return Base64.getEncoder().encodeToString(artifact);
        } catch (NoSuchAlgorithmException e) {
            throw new ArtifactResolverProcessingException("JVM does not support required cryptography algorithms: SHA-256/SHA256PRNG.", e);
        } catch (IOException e) {
            throw new ArtifactResolverProcessingException(e);
        }

    }

    @Override
    public void close() {

    }

}
