
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import com.github.cfrg.aegis.Aegis256;
import com.github.cfrg.aegis.VerificationFailedException;

public class TestAegis256 {

    @Test
    public void roundTripDetached() throws VerificationFailedException {
        final var key = Aegis256.keygen();
        final var nonce = Aegis256.noncegen();
        final var plaintext = "0123456789abcdef0123456789ABCDEF".getBytes();
        final var ad = "Additional data".getBytes();

        var aegis = new Aegis256(key, nonce, 16);
        final var ac = aegis.encryptDetached(plaintext, ad);

        aegis = new Aegis256(key, nonce, 16);
        var recovered_plaintext = aegis.decryptDetached(ac, ad);
        assertArrayEquals(plaintext, recovered_plaintext);
    }

    @Test
    public void roundTripAttached() throws VerificationFailedException {
        final var key = Aegis256.keygen();
        final var nonce = Aegis256.noncegen();
        final var plaintext = "0123456789abcdef0123456789ABCDEF".getBytes();
        final var ad = "Additional data".getBytes();

        var aegis = new Aegis256(key, nonce, 16);
        var ciphertext = aegis.encrypt(plaintext, ad);

        aegis = new Aegis256(key, nonce, 16);
        var recovered_plaintext = aegis.decrypt(ciphertext, ad);
        assertArrayEquals(plaintext, recovered_plaintext);
    }

}
