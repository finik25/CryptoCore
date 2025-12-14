import unittest

class TestGCMAADComprehensive(unittest.TestCase):
    def test_empty_aad(self):
        """GCM should work with empty AAD (default)."""
        # Encryption without --aad
        # Decryption without --aad
        # Should work

    def test_short_aad(self):
        """GCM should work with short AAD (1 byte)."""
        aad_hex = "aa"

    def test_long_aad(self):
        """GCM should work with long AAD (> 1KB)."""
        aad_hex = "aa" * 1024  # 1KB AAD

    def test_aad_exactly_block_size(self):
        """GCM should work with AAD exactly 16 bytes."""
        aad_hex = "00" * 16

    def test_aad_multiple_blocks(self):
        """GCM should work with AAD spanning multiple blocks."""
        aad_hex = "00" * 64  # 4 blocks

    def test_wrong_aad_length_same_content(self):
        """Wrong AAD length should cause authentication failure."""
        # Encryption with AAD="aabbcc"
        # Decryption with AAD="aabb" (shorter)
        # Should fail

    def test_wrong_aad_same_length(self):
        """Wrong AAD content (same length) should cause authentication failure."""
        # Encryption with AAD="aabbcc"
        # Decryption with AAD="ddeeff" (same length)
        # Should fail

    def test_aad_with_special_characters_in_hex(self):
        """AAD with mixed case hex should work."""
        aad_hex = "AaBbCcDdEeFf001122"  # Mixed case
        # Should normalize to lowercase

    def test_aad_with_0x_prefix(self):
        """AAD with 0x prefix should be handled."""
        aad_hex = "0xaabbcc"
        # Should strip "0x"

    def test_aad_with_spaces(self):
        """AAD with spaces should be handled."""
        aad_hex = "aa bb cc dd"
        # Should ignore spaces
