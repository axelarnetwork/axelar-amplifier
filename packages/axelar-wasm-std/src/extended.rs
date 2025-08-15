pub struct Extended<T> {
    pub value: T,
    pub additional: BTreeMap<String, Value>,
}
