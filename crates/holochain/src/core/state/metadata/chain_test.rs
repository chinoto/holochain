use crate::fixt::*;
use fallible_iterator::FallibleIterator;
use fixt::prelude::*;
use hdk3::prelude::Create;
use holo_hash::{AgentPubKey, HeaderHash};
use holochain_state::{
    env::ReadManager,
    test_utils::{test_cell_env, TestEnvironment},
};
use holochain_zome_types::{test_utils::fake_agent_pubkey_1, Header};

use super::{ChainItemKey, MetadataBuf, MetadataBufT};

fn setup() -> (TestEnvironment, MetadataBuf, Create, Create, AgentPubKey) {
    observability::test_run().ok();
    let test_env = test_cell_env();
    let meta_buf = MetadataBuf::vault(test_env.env().into()).unwrap();
    let agent_pubkey = fake_agent_pubkey_1();
    let mut h1 = fixt!(Create);
    let mut h2 = fixt!(Create);
    h1.author = agent_pubkey.clone();
    h2.author = agent_pubkey.clone();
    (test_env, meta_buf, h1, h2, agent_pubkey)
}

#[tokio::test(threaded_scheduler)]
async fn check_different_seq_num_on_separate_queries() {
    let (_te, mut meta_buf, mut h1, mut h2, agent_pubkey) = setup();
    h1.header_seq = 1;
    h2.header_seq = 2;
    meta_buf.register_activity(&h1.into()).unwrap();
    meta_buf.register_activity(&h2.into()).unwrap();

    let g = meta_buf.env().guard();
    let reader = g.reader().unwrap();

    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 1);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        1
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 2);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        1
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 0);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        0
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 3);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        0
    );
}

#[tokio::test(threaded_scheduler)]
async fn check_equal_seq_num_on_same_query() {
    let (_te, mut meta_buf, mut h1, mut h2, agent_pubkey) = setup();
    h1.header_seq = 1;
    h2.header_seq = 1;
    let h1: Header = h1.into();
    let h2: Header = h2.into();
    meta_buf.register_activity(&h1).unwrap();
    meta_buf.register_activity(&h2).unwrap();

    let g = meta_buf.env().guard();
    let reader = g.reader().unwrap();

    let k = ChainItemKey::from(&h1);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        1
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 1);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        2
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 2);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        0
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 0);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        0
    );
    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 3);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        0
    );
}

#[tokio::test(threaded_scheduler)]
async fn chain_item_keys_ser() {
    let (_te, mut meta_buf, mut h, _, agent_pubkey) = setup();
    h.header_seq = 1;
    let h = Header::Create(h);
    let expect_hash = HeaderHash::with_data_sync(&h);
    meta_buf.register_activity(&h).unwrap();

    let g = meta_buf.env().guard();
    let reader = g.reader().unwrap();

    let k = ChainItemKey::from(&h);
    assert_eq!(
        meta_buf.get_activity(&reader, k).unwrap().count().unwrap(),
        1
    );

    let k = ChainItemKey::AgentSequence(agent_pubkey.clone(), 1);
    let mut headers: Vec<_> = meta_buf
        .get_activity(&reader, k)
        .unwrap()
        .collect()
        .unwrap();
    assert_eq!(headers.len(), 1);
    println!("expect hash {:?}", expect_hash.clone().into_inner());
    assert_eq!(headers.pop().unwrap().header_hash, expect_hash);
}
