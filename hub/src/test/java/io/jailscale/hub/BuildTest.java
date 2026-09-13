package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** The build identity the status page prints (ARCHITECTURE.md §11.2: self-reported, and labelled so). */
class BuildTest {

    /** The published vector for "abc", so the hex encoding is checked against something external. */
    @Test
    void theDigestIsSha256InLowercaseHex() throws Exception {
        Path dir = TestDirs.newRoot("build");
        Path f = dir.resolve("abc");
        Files.writeString(f, "abc");
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Build.sha256(f));
    }

    /** A binary is hundreds of buffers long, so the loop has to hash all of them and each once. */
    @Test
    void aFileLongerThanTheBufferHashesEntirelyAndOnce() throws Exception {
        Path f = TestDirs.newRoot("build").resolve("big");
        byte[] data = new byte[(64 * 1024) * 3 + 977];
        new Random(7).nextBytes(data);
        Files.write(f, data);

        StringBuilder expected = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(data)) {
            expected.append(String.format("%02x", b));
        }
        assertEquals(expected.toString(), Build.sha256(f));
    }

    /**
     * Tests run on a JVM, where the executable is the JVM: its digest would be a true answer to a
     * question nobody asked, so there is no answer instead.
     */
    @Test
    void aJarOnAJvmReportsNoBinary() {
        assertNull(Build.executableSha256());
    }
}
