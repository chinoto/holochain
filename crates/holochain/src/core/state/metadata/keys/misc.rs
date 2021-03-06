use std::marker::PhantomData;

use super::*;

#[derive(PartialOrd, Ord, PartialEq, Eq, derive_more::AsRef, Debug, Clone)]
#[as_ref(forward)]
pub struct MiscMetaKey<P>
where
    P: PrefixType,
{
    prefix_and_bytes: Vec<u8>,
    #[as_ref(ignore)]
    __phantom: PhantomData<P>,
}
#[derive(PartialOrd, Clone, Ord, PartialEq, Eq, Debug)]
pub struct EntryStatusPrefix;
impl PrefixType for EntryStatusPrefix {
    const PREFIX: u8 = 0x0;
}

#[derive(PartialOrd, Clone, Ord, PartialEq, Eq, Debug)]
pub struct StoreElementPrefix;
impl PrefixType for StoreElementPrefix {
    const PREFIX: u8 = 0x1;
}

#[derive(PartialOrd, Clone, Ord, PartialEq, Eq, Debug)]
pub struct ChainItemPrefix;
impl PrefixType for ChainItemPrefix {
    const PREFIX: u8 = 0x2;
}

impl<P: PrefixType> MiscMetaKey<P> {
    /// Create a new prefix bytes key
    pub fn new<I: IntoIterator<Item = u8>>(bytes: I) -> Self {
        Self {
            prefix_and_bytes: std::iter::once(P::PREFIX).chain(bytes).collect(),
            __phantom: PhantomData,
        }
    }
    /// Get the bytes without the prefix
    pub fn without_prefix(&self) -> &[u8] {
        &self.prefix_and_bytes[1..]
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize, Deserialize)]
/// Values for the misc kv
/// Matches the key
pub enum MiscMetaValue {
    /// Collapsed status of an entry
    EntryStatus(EntryDhtStatus),
    /// We have integrated a StoreElement for this key
    StoreElement,
    /// There is a header at this key.
    /// We store the timestamp so headers can be ordered.
    ChainItem(Timestamp),
}

impl MiscMetaKey<EntryStatusPrefix> {
    /// Create an entry status key
    pub fn entry_status(hash: &EntryHash) -> MiscMetaKey<EntryStatusPrefix> {
        let bytes: SerializedBytes = hash.try_into().expect("Entry Hash can't fail to serialize");
        MiscMetaKey::new(bytes.bytes().iter().copied())
    }
}

impl MiscMetaKey<StoreElementPrefix> {
    /// Create a store entry key
    pub fn store_element(hash: &HeaderHash) -> MiscMetaKey<StoreElementPrefix> {
        let bytes: SerializedBytes = hash
            .try_into()
            .expect("Header Hash can't fail to serialize");
        MiscMetaKey::new(bytes.bytes().iter().copied())
    }
}

impl MiscMetaKey<ChainItemPrefix> {
    /// Create an chain item key
    pub fn chain_item(key: &ChainItemKey) -> MiscMetaKey<ChainItemPrefix> {
        let bytes: BytesKey = key.into();
        MiscMetaKey::new(bytes.0.into_iter())
    }
}

impl<PM, PB> From<MiscMetaKey<PM>> for PrefixBytesKey<PB>
where
    PM: PrefixType,
    PB: PrefixType,
{
    fn from(k: MiscMetaKey<PM>) -> Self {
        Self::new(k.prefix_and_bytes.into_iter())
    }
}

impl<PM, PB> From<PrefixBytesKey<PB>> for MiscMetaKey<PM>
where
    PM: PrefixType,
    PB: PrefixType,
{
    fn from(key: PrefixBytesKey<PB>) -> Self {
        Self {
            prefix_and_bytes: key.without_prefix().to_owned(),
            __phantom: PhantomData,
        }
    }
}

impl MiscMetaValue {
    pub fn entry_status(self) -> EntryDhtStatus {
        match self {
            MiscMetaValue::EntryStatus(e) => e,
            _ => unreachable!("Tried to go from {:?} to {:?}", self, "entry_status"),
        }
    }

    pub fn chain_item(self) -> Timestamp {
        match self {
            MiscMetaValue::ChainItem(t) => t,
            _ => unreachable!("Tried to go from {:?} to {:?}", self, "chain_item"),
        }
    }

    pub fn new_store_element() -> Self {
        Self::StoreElement
    }
}

impl From<MiscMetaKey<ChainItemPrefix>> for ChainItemKey {
    fn from(k: MiscMetaKey<ChainItemPrefix>) -> Self {
        let bytes: BytesKey = k.without_prefix().into();
        bytes.into()
    }
}
