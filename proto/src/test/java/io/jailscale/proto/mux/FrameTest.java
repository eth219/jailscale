package io.jailscale.proto.mux;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class FrameTest {

    @Test
    void encodesHeaderBigEndian() {
        // A flags byte of 0x01: no flag is defined any more (FLAG_DGRAM went with raw UDP, §8.4),
        // and what this asserts is the header's layout, which has to keep a place for one.
        Frame f = new Frame(0x01020304L, Frame.DATA, 0x01, new byte[] {9, 8});
        assertEquals("01020304" + "02" + "01" + "0002" + "0908", HexFormat.of().formatHex(f.encode()));
    }

    @Test
    void decodeRoundTrip() throws Exception {
        Frame[] frames = {
            Frame.ctrl("{\"t\":\"Ping\",\"id\":1}".getBytes()),
            Frame.keepalive(),
            Frame.data(42, new byte[Frame.MAX_DATA]),
            Frame.close(7),
            Frame.rst(7, 3),
            Frame.window(9, 256 * 1024),
            new Frame(0xFFFFFFFFL, Frame.OPEN, 0, "{}".getBytes()),
        };
        for (Frame f : frames) {
            Frame d = Frame.decode(f.encode());
            assertEquals(f.streamId(), d.streamId());
            assertEquals(f.type(), d.type());
            assertEquals(f.flags(), d.flags());
            assertArrayEquals(f.payload(), d.payload());
        }
        assertEquals(256 * 1024, Frame.window(9, 256 * 1024).windowDelta());
        assertEquals(0xFFFFFFFFL, Frame.decode(frames[6].encode()).streamId());
    }

    @Test
    void rejectsBadFrames() {
        assertThrows(MuxException.class, () -> Frame.decode(new byte[7]));
        byte[] lenMismatch = Frame.close(1).encode();
        lenMismatch[7] = 5;
        assertThrows(MuxException.class, () -> Frame.decode(lenMismatch));
        // A type this build has no case for parses (ARCHITECTURE.md §5.4) and is skipped by the
        // dispatcher; only a type that cannot be on the wire at all is refused here.
        byte[] futureType = Frame.close(1).encode();
        futureType[4] = 99;
        assertEquals(99, assertDoesNotThrow(() -> Frame.decode(futureType)).type());
        byte[] zeroType = Frame.close(1).encode();
        zeroType[4] = 0;
        assertThrows(MuxException.class, () -> Frame.decode(zeroType));
        assertThrows(IllegalArgumentException.class, () -> Frame.data(1, new byte[Frame.MAX_DATA + 1]));
        assertThrows(IllegalArgumentException.class, () -> new Frame(1, Frame.CTRL, 0, new byte[Frame.MAX_PAYLOAD + 1]));
        assertThrows(IllegalArgumentException.class, () -> Frame.window(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new Frame(-1, Frame.DATA, 0, null));
    }
}
