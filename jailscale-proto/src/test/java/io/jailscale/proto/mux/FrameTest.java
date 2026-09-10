package io.jailscale.proto.mux;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class FrameTest {

    @Test
    void encodesHeaderBigEndian() {
        Frame f = new Frame(0x01020304L, Frame.DATA, Frame.FLAG_DGRAM, new byte[] {9, 8});
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
        byte[] badType = Frame.close(1).encode();
        badType[4] = 99;
        assertThrows(MuxException.class, () -> Frame.decode(badType));
        assertThrows(IllegalArgumentException.class, () -> Frame.data(1, new byte[Frame.MAX_DATA + 1]));
        assertThrows(IllegalArgumentException.class, () -> new Frame(1, Frame.CTRL, 0, new byte[Frame.MAX_PAYLOAD + 1]));
        assertThrows(IllegalArgumentException.class, () -> Frame.window(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new Frame(-1, Frame.DATA, 0, null));
    }
}
