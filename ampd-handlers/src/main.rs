fn get_greeting() -> &'static str {
    "Hello from AMPD handler!"
}

fn main() {
    println!("{}", get_greeting());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greeting() {
        assert_eq!(get_greeting(), "Hello from AMPD handler!");
    }
}
