pub trait VecExt<T> {
    fn to_none_if_empty(self) -> Option<Vec<T>>;
}

impl<T> VecExt<T> for Vec<T> {
    fn to_none_if_empty(self) -> Option<Vec<T>> {
        if self.is_empty() {
            None
        } else {
            Some(self)
        }
    }
}
