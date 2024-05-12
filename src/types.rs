pub type u8x32 = [u8; 32];

impl hex::ToHex for u8x32 {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.to_hex().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.to_hex().encode_hex_upper()
    }
}
