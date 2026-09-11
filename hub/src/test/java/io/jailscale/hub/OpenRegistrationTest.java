package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.jailscale.proto.control.Message;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §11.5. With registration open, a knock registers straight away and presents no
 * credential, so the credential bucket never sees it. Without a limit of its own one address could
 * register nodes without bound and claim public names under the hub domain. The design document
 * used to claim this limit existed; it did not.
 */
@Timeout(60)
class OpenRegistrationTest {

    private Path root;
    private Store store;
    private Registrar registrar;

    @BeforeEach
    void setUp() throws Exception {
        root = TestDirs.newRoot("or");
        store = new Store(root.resolve("hub"));
        store.setSetting(Store.SETTING_REGISTRATION, "open");
        store.setSetting(Store.SETTING_KNOCK, "on");
        registrar = new Registrar(null, store);
    }

    @AfterEach
    void tearDown() throws Exception {
        store.close();
    }

    private Message.RegisterResponse knock(String mkey, String ip) throws Exception {
        return registrar.decide(mkey, new Message.RegisterRequest("host-" + mkey, "linux", null, null, null, null), ip)
            .response();
    }

    @Test
    void oneAddressCannotRegisterWithoutBound() throws Exception {
        for (int i = 0; i < Registrar.OPEN_BURST; i++) {
            assertEquals(Message.RegisterResponse.APPROVED, knock("mkey" + i, "203.0.113.7").status(),
                "the burst should be spendable in one go");
        }
        assertEquals(Message.RegisterResponse.REJECTED, knock("mkeyN", "203.0.113.7").status(),
            "past the burst, the same address is refused");
        assertEquals("rate-limited", knock("mkeyM", "203.0.113.7").reason());
    }

    @Test
    void anotherAddressIsUnaffected() throws Exception {
        for (int i = 0; i < Registrar.OPEN_BURST + 3; i++) {
            knock("noisy" + i, "203.0.113.7");
        }
        assertEquals(Message.RegisterResponse.APPROVED, knock("elsewhere", "198.51.100.4").status(),
            "the bucket is per address, not global");
    }

    @Test
    void aNodeThatAlreadyRegisteredIsNotThrottled() throws Exception {
        assertEquals(Message.RegisterResponse.APPROVED, knock("known", "203.0.113.7").status());
        for (int i = 0; i < Registrar.OPEN_BURST + 5; i++) {
            knock("other" + i, "203.0.113.7");
        }
        // Reconnecting returns before any limit is consulted, so a busy address cannot lock out
        // the nodes it already has.
        assertEquals(Message.RegisterResponse.APPROVED, knock("known", "203.0.113.7").status());
        assertNotNull(store.node("known"));
    }
}
