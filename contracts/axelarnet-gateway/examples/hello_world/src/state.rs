use cw_storage_plus::Item;

pub const LAST_MESSAGE: Item<String> = Item::new("last_message");
