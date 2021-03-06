use dexios_core::primitives::Algorithm;
use dexios_core::stream::Progress;

#[derive(Clone, Debug)]
pub enum Direction {
    Encrypt,
    Decrypt,
}


pub struct Config {
    pub direction: Direction,
    pub algorithm: Algorithm,
    pub password: String,
    pub filename: Option<String>,
    pub out_file: Option<String>,
    pub ui: Box<dyn Progress>,
}

impl Config {
    pub fn new(
        _direction: Direction,
        algorithm: Algorithm,
        password: String,
        filename: Option<String>,
        out_file: Option<String>,
        ui: Box<dyn Progress>,
    ) -> Self {
        let direction: Direction = _direction.clone();
        Config {
            direction,
            algorithm,
            password,
            filename,
            out_file,
            ui,
        }
    }
}
