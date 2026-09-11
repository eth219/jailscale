package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §10 and §11.2. The hub keys admin rights and name ownership on the user name
 * string, so whoever may choose that string may choose who they are. A joining node chooses its own
 * unless the credential names one, and nothing used to stop it choosing a name that already meant
 * someone: joining as "alice" was enough to be alice, admin rights and her names included.
 */
@Timeout(60)
class UserIdentityTest {

    private Path root;
    private Store store;
    private Registrar registrar;

    @BeforeEach
    void setUp() throws Exception {
        root = TestDirs.newRoot("ui");
        store = new Store(root.resolve("hub"));
        store.setSetting(Store.SETTING_REGISTRATION, "open");
        registrar = new Registrar(null, store, new Bans(store));
    }

    @AfterEach
    void tearDown() throws Exception {
        store.close();
    }

    private Message.RegisterResponse join(String mkey, String asUser) throws Exception {
        return registrar.decide(mkey, new Message.RegisterRequest("host", "linux", asUser, null, null, null), "203.0.113.7")
            .response();
    }

    /** An invite as the store holds it, returning the token the joiner would present. */
    private String invite(String user) throws Exception {
        String token = Tokens.inviteToken();
        store.createInvite(token, Tokens.normalizeCode(Tokens.shortCode()), user, 1, 3600, 600, "alice", false);
        return token;
    }

    private Message.RegisterResponse joinWithInvite(String mkey, String token, String asUser) throws Exception {
        return registrar.decide(mkey, new Message.RegisterRequest("host", "linux", asUser, token, null, null), "203.0.113.7")
            .response();
    }

    @Test
    void aJoinerCannotPickAnExistingUsersName() throws Exception {
        assertEquals(Message.RegisterResponse.APPROVED, join("m_alice", "alice").status());
        assertTrue(store.isAdmin("alice"), "the first node bootstraps the admin list");

        Message.RegisterResponse second = join("m_mallory", "alice");
        assertEquals(Message.RegisterResponse.REJECTED, second.status());
        assertEquals("user-taken", second.reason());
        assertEquals(1, store.nodes().size());

        // A name nobody holds is still free, and it does not come with alice's rights.
        assertEquals(Message.RegisterResponse.APPROVED, join("m_mallory", "mallory").status());
        assertFalse(store.isAdmin("mallory"));
    }

    @Test
    void aUserExistsWithoutANode() throws Exception {
        assertEquals(Message.RegisterResponse.APPROVED, join("m_alice", "alice").status());

        // An admin listed before their machine has joined is already someone.
        store.addAdmin("carol");
        assertEquals("user-taken", join("m_mallory", "carol").reason());

        // So is a user whose machines are gone: names and domains stay theirs until the operator
        // releases them, and a stranger joining under the name would inherit them.
        store.claimName("shared", "bob", "m_bob", "127.0.0.1:1");
        store.claimDomain("bob.example", "bob", "m_bob");
        assertFalse(store.users().contains("bob"));
        assertTrue(store.userExists("bob"));
        assertEquals("user-taken", join("m_mallory", "bob").reason());
        assertEquals(Message.RegisterResponse.APPROVED, join("m_mallory", "mallory").status());
    }

    @Test
    void anInviteThatNamesTheUserIsHowASecondMachineJoins() throws Exception {
        assertEquals(Message.RegisterResponse.APPROVED, join("m_alice", "alice").status());

        // Pinned to alice by someone the hub let name her: her own machine, or an admin.
        String pinned = invite("alice");
        Message.RegisterResponse r = joinWithInvite("m_alice2", pinned, null);
        assertEquals(Message.RegisterResponse.APPROVED, r.status());
        assertEquals("alice", r.user());
        assertEquals(2, store.nodes().size());

        // An invite that names nobody leaves the choice to the redeemer, which is not the same
        // authority: it cannot be spent on becoming alice.
        Message.RegisterResponse taken = joinWithInvite("m_mallory", invite(null), "alice");
        assertEquals("user-taken", taken.reason());
    }

    @Test
    void approvingAKnockDoesNotHandOverAnExistingIdentity() throws Exception {
        assertEquals(Message.RegisterResponse.APPROVED, join("m_alice", "alice").status());
        store.setSetting(Store.SETTING_REGISTRATION, "invite");

        assertEquals(Message.RegisterResponse.PENDING, join("m_mallory", "alice").status());
        // The knock suggested "alice". Approving it on autopilot would hand a stranger her account.
        assertThrows(IllegalArgumentException.class, () -> registrar.approvePending("m_mallory", null));
        // The operator naming someone deliberately is their call, and still works.
        assertEquals("mallory", registrar.approvePending("m_mallory", "mallory").user());
    }
}
