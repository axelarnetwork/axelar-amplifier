pub trait FnExt: Sized {
    fn then<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}

impl<T> FnExt for T {}

#[cfg(test)]
mod tests {
    use crate::fn_ext::FnExt;

    #[derive(Debug)]
    struct Foo {
        s: String,
    }

    #[test]
    fn pipe_value() {
        let foo = Foo {
            s: "hello".to_string(),
        };
        assert_eq!(foo.then(|foo| foo.s + " world"), "hello world");
    }
}
