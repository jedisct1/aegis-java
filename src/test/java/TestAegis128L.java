
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import com.github.cfrg.aegis.Aegis128L;
import com.github.cfrg.aegis.VerificationFailedException;

public class TestAegis128L {

    @Test
    public void roundTripDetached() throws VerificationFailedException {
        final var key = Aegis128L.keygen();
        final var nonce = Aegis128L.noncegen();
        final var plaintext = "0123456789abcdef0123456789ABCDEF".getBytes();
        final var ad = "Additional data".getBytes();

        var aegis = new Aegis128L(key, nonce, 16);
        final var ac = aegis.encryptDetached(plaintext, ad);

        aegis = new Aegis128L(key, nonce, 16);
        var recovered_plaintext = aegis.decryptDetached(ac, ad);
        assertArrayEquals(plaintext, recovered_plaintext);
    }

    @Test
    public void roundTripAttached() throws VerificationFailedException {
        final var key = Aegis128L.keygen();
        final var nonce = Aegis128L.noncegen();
        final var plaintext = "0123456789abcdef0123456789ABCDEF".getBytes();
        final var ad = "Additional data".getBytes();

        var aegis = new Aegis128L(key, nonce, 16);
        var ciphertext = aegis.encrypt(plaintext, ad);

        aegis = new Aegis128L(key, nonce, 16);
        var recovered_plaintext = aegis.decrypt(ciphertext, ad);
        assertArrayEquals(plaintext, recovered_plaintext);
    }

}
