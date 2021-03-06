//! A Ribosome is a structure which knows how to execute hApp code.
//!
//! We have only one instance of this: [WasmRibosome]. The abstract trait exists
//! so that we can write mocks against the `RibosomeT` interface, as well as
//! opening the possiblity that we might support applications written in other
//! languages and environments.

// This allow is here because #[automock] automaticaly creates a struct without
// documentation, and there seems to be no way to add docs to it after the fact
pub mod error;
pub mod guest_callback;
pub mod host_fn;
pub mod wasm_ribosome;

use crate::core::ribosome::guest_callback::entry_defs::EntryDefsInvocation;
use crate::core::ribosome::guest_callback::entry_defs::EntryDefsResult;
use crate::core::ribosome::guest_callback::init::InitInvocation;
use crate::core::ribosome::guest_callback::init::InitResult;
use crate::core::ribosome::guest_callback::migrate_agent::MigrateAgentInvocation;
use crate::core::ribosome::guest_callback::migrate_agent::MigrateAgentResult;
use crate::core::ribosome::guest_callback::post_commit::PostCommitInvocation;
use crate::core::ribosome::guest_callback::post_commit::PostCommitResult;
use crate::core::ribosome::guest_callback::validate::ValidateInvocation;
use crate::core::ribosome::guest_callback::validate::ValidateResult;
use crate::core::ribosome::guest_callback::validate_link::ValidateLinkHostAccess;
use crate::core::ribosome::guest_callback::validate_link::ValidateLinkInvocation;
use crate::core::ribosome::guest_callback::validate_link::ValidateLinkResult;
use crate::core::ribosome::guest_callback::validation_package::ValidationPackageInvocation;
use crate::core::ribosome::guest_callback::validation_package::ValidationPackageResult;
use crate::core::ribosome::guest_callback::CallIterator;
use crate::core::workflow::CallZomeWorkspaceLock;
use crate::fixt::ExternInputFixturator;
use crate::fixt::FunctionNameFixturator;
use crate::fixt::ZomeNameFixturator;
use crate::{conductor::interface::SignalBroadcaster, core::ribosome::error::RibosomeError};
use ::fixt::prelude::*;
use derive_more::Constructor;
use error::RibosomeResult;
use guest_callback::{
    entry_defs::EntryDefsHostAccess, init::InitHostAccess, migrate_agent::MigrateAgentHostAccess,
    post_commit::PostCommitHostAccess, validate::ValidateHostAccess,
    validation_package::ValidationPackageHostAccess,
};
use holo_hash::fixt::AgentPubKeyFixturator;
use holo_hash::AgentPubKey;
use holochain_keystore::KeystoreSender;
use holochain_p2p::HolochainP2pCell;
use holochain_serialized_bytes::prelude::*;
use holochain_types::cell::CellId;
use holochain_types::dna::zome::HostFnAccess;
use holochain_types::dna::DnaFile;
use holochain_types::fixt::CapSecretFixturator;
use holochain_types::fixt::CellIdFixturator;
use holochain_wasm_test_utils::TestWasm;
use holochain_zome_types::capability::CapGrant;
use holochain_zome_types::zome::FunctionName;
use holochain_zome_types::zome::ZomeName;
use holochain_zome_types::ExternOutput;
use holochain_zome_types::ZomeCallResponse;
use holochain_zome_types::{capability::CapSecret, header::ZomeId, ExternInput};
use mockall::automock;
use std::iter::Iterator;

#[derive(Clone)]
pub struct CallContext {
    pub zome_name: ZomeName,
    pub host_access: HostAccess,
}

impl CallContext {
    pub fn new(zome_name: ZomeName, host_access: HostAccess) -> Self {
        Self {
            zome_name,
            host_access,
        }
    }

    pub fn zome_name(&self) -> ZomeName {
        self.zome_name.clone()
    }
    pub fn host_access(&self) -> HostAccess {
        self.host_access.clone()
    }
}

#[derive(Clone)]
pub enum HostAccess {
    ZomeCall(ZomeCallHostAccess),
    Validate(ValidateHostAccess),
    ValidateCreateLink(ValidateLinkHostAccess),
    Init(InitHostAccess),
    EntryDefs(EntryDefsHostAccess),
    MigrateAgent(MigrateAgentHostAccess),
    ValidationPackage(ValidationPackageHostAccess),
    PostCommit(PostCommitHostAccess), // TODO: add emit_signal access here?
}

impl From<&HostAccess> for HostFnAccess {
    fn from(host_access: &HostAccess) -> Self {
        match host_access {
            HostAccess::ZomeCall(zome_call_host_access) => zome_call_host_access.into(),
            HostAccess::Validate(validate_host_access) => validate_host_access.into(),
            HostAccess::ValidateCreateLink(validate_link_add_host_access) => {
                validate_link_add_host_access.into()
            }
            HostAccess::Init(init_host_access) => init_host_access.into(),
            HostAccess::EntryDefs(entry_defs_host_access) => entry_defs_host_access.into(),
            HostAccess::MigrateAgent(migrate_agent_host_access) => migrate_agent_host_access.into(),
            HostAccess::ValidationPackage(validation_package_host_access) => {
                validation_package_host_access.into()
            }
            HostAccess::PostCommit(post_commit_host_access) => post_commit_host_access.into(),
        }
    }
}

impl HostAccess {
    /// Get the workspace, panics if none was provided
    pub fn workspace(&self) -> &CallZomeWorkspaceLock {
        match self {
            Self::ZomeCall(ZomeCallHostAccess{workspace, .. }) |
            Self::Init(InitHostAccess{workspace, .. }) |
            Self::MigrateAgent(MigrateAgentHostAccess{workspace, .. }) |
            Self::ValidationPackage(ValidationPackageHostAccess{workspace, .. }) |
            Self::PostCommit(PostCommitHostAccess{workspace, .. }) |
            Self::Validate(ValidateHostAccess { workspace, .. }) |
            Self::ValidateCreateLink(ValidateLinkHostAccess { workspace, .. }) => {
                workspace
            }
            _ => panic!("Gave access to a host function that uses the workspace without providing a workspace"),
        }
    }

    /// Get the keystore, panics if none was provided
    pub fn keystore(&self) -> &KeystoreSender {
        match self {
            Self::ZomeCall(ZomeCallHostAccess{keystore, .. }) |
            Self::Init(InitHostAccess{keystore, .. }) |
            Self::PostCommit(PostCommitHostAccess{keystore, .. }) => {
                keystore
            }
            _ => panic!("Gave access to a host function that uses the keystore without providing a keystore"),
        }
    }

    /// Get the network, panics if none was provided
    pub fn network(&self) -> &HolochainP2pCell {
        match self {
            Self::ZomeCall(ZomeCallHostAccess { network, .. })
            | Self::Init(InitHostAccess { network, .. })
            | Self::PostCommit(PostCommitHostAccess { network, .. })
            | Self::Validate(ValidateHostAccess { network, .. })
            | Self::ValidateCreateLink(ValidateLinkHostAccess { network, .. }) => network,
            _ => panic!(
                "Gave access to a host function that uses the network without providing a network"
            ),
        }
    }

    /// Get the signal broadcaster, panics if none was provided
    pub fn signal_tx(&mut self) -> &mut SignalBroadcaster {
        match self {
            Self::ZomeCall(ZomeCallHostAccess { signal_tx, .. }) => signal_tx,
            _ => panic!(
                "Gave access to a host function that uses the signal broadcaster without providing one"
            ),
        }
    }

    /// Get the associated CellId, panics if not applicable
    pub fn cell_id(&self) -> &CellId {
        match self {
            Self::ZomeCall(ZomeCallHostAccess { cell_id, .. }) => cell_id,
            _ => panic!("Gave access to a host function that references a CellId"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FnComponents(pub Vec<String>);

/// iterating over FnComponents isn't as simple as returning the inner Vec iterator
/// we return the fully joined vector in specificity order
/// specificity is defined as consisting of more components
/// e.g. FnComponents(Vec("foo", "bar", "baz")) would return:
/// - Some("foo_bar_baz")
/// - Some("foo_bar")
/// - Some("foo")
/// - None
impl Iterator for FnComponents {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        match self.0.len() {
            0 => None,
            _ => {
                let ret = self.0.join("_");
                self.0.pop();
                Some(ret)
            }
        }
    }
}

impl From<Vec<String>> for FnComponents {
    fn from(vs: Vec<String>) -> Self {
        Self(vs)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ZomesToInvoke {
    All,
    One(ZomeName),
}

impl ZomesToInvoke {
    pub fn one(zome_name: ZomeName) -> Self {
        Self::One(zome_name)
    }
}

pub trait Invocation: Clone {
    /// Some invocations call into a single zome and some call into many or all zomes.
    /// An example of an invocation that calls across all zomes is init. Init must pass for every
    /// zome in order for the Dna overall to successfully init.
    /// An example of an invocation that calls a single zome is validation of an entry, because
    /// the entry is only defined in a single zome, so it only makes sense for that exact zome to
    /// define the validation logic for that entry.
    /// In the future this may be expanded to support a subset of zomes that is larger than one.
    /// For example, we may want to trigger a callback in all zomes that implement a
    /// trait/interface, but this doesn't exist yet, so the only valid options are All or One.
    fn zomes(&self) -> ZomesToInvoke;
    /// Invocations execute in a "sparse" manner of decreasing specificity. In technical terms this
    /// means that the list of strings in FnComponents will be concatenated into a single function
    /// name to be called, then the last string will be removed and a shorter function name will
    /// be attempted and so on until all variations have been attempted.
    /// For example, if FnComponents was vec!["foo", "bar", "baz"] it would loop as "foo_bar_baz"
    /// then "foo_bar" then "foo". All of those three callbacks that are defined will be called
    /// _unless a definitive callback result is returned_.
    /// @see CallbackResult::is_definitive() in zome_types.
    /// All of the individual callback results are then folded into a single overall result value
    /// as a From implementation on the invocation results structs (e.g. zome results vs. ribosome
    /// results).
    fn fn_components(&self) -> FnComponents;
    /// the serialized input from the host for the wasm call
    /// this is intentionally NOT a reference to self because ExternInput may be huge we want to be
    /// careful about cloning invocations
    fn host_input(self) -> Result<ExternInput, SerializedBytesError>;
}

impl ZomeCallInvocation {
    /// to decide if a zome call is authorized:
    /// - we need to find a live (committed and not deleted) cap grant that matches the secret
    /// - if the live cap grant is for the current author the call is ALWAYS authorized ELSE
    /// - the live cap grant needs to include the invocation's provenance AND zome/function name
    #[allow(clippy::extra_unused_lifetimes)]
    pub fn is_authorized<'a>(&self, host_access: &ZomeCallHostAccess) -> RibosomeResult<bool> {
        let check_function = (self.zome_name.clone(), self.fn_name.clone());
        let check_agent = self.provenance.clone();
        let check_secret = self.cap;

        tokio_safe_block_on::tokio_safe_block_forever_on(async move {
            let maybe_grant: Option<CapGrant> = host_access
                .workspace
                .read()
                .await
                .source_chain
                .valid_cap_grant(&check_function, &check_agent, check_secret.as_ref())?;

            Ok(maybe_grant.is_some())
        })
    }
}

mockall::mock! {
    Invocation {}
    trait Invocation {
        fn zomes(&self) -> ZomesToInvoke;
        fn fn_components(&self) -> FnComponents;
        fn host_input(self) -> Result<ExternInput, SerializedBytesError>;
    }
    trait Clone {
        fn clone(&self) -> Self;
    }
}

/// A top-level call into a zome function,
/// i.e. coming from outside the Cell from an external Interface
#[allow(missing_docs)] // members are self-explanitory
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZomeCallInvocation {
    /// The ID of the [Cell] in which this Zome-call would be invoked
    pub cell_id: CellId,
    /// The name of the Zome containing the function that would be invoked
    pub zome_name: ZomeName,
    /// The capability request authorization required
    pub cap: Option<CapSecret>,
    /// The name of the Zome function to call
    pub fn_name: FunctionName,
    /// The serialized data to pass an an argument to the Zome call
    pub payload: ExternInput,
    /// the provenance of the call
    pub provenance: AgentPubKey,
}

fixturator!(
    ZomeCallInvocation;
    curve Empty ZomeCallInvocation {
        cell_id: CellIdFixturator::new(Empty).next().unwrap(),
        zome_name: ZomeNameFixturator::new(Empty).next().unwrap(),
        cap: Some(CapSecretFixturator::new(Empty).next().unwrap()),
        fn_name: FunctionNameFixturator::new(Empty).next().unwrap(),
        payload: ExternInputFixturator::new(Empty).next().unwrap(),
        provenance: AgentPubKeyFixturator::new(Empty).next().unwrap(),
    };
    curve Unpredictable ZomeCallInvocation {
        cell_id: CellIdFixturator::new(Unpredictable).next().unwrap(),
        zome_name: ZomeNameFixturator::new(Unpredictable).next().unwrap(),
        cap: Some(CapSecretFixturator::new(Unpredictable).next().unwrap()),
        fn_name: FunctionNameFixturator::new(Unpredictable).next().unwrap(),
        payload: ExternInputFixturator::new(Unpredictable).next().unwrap(),
        provenance: AgentPubKeyFixturator::new(Unpredictable).next().unwrap(),
    };
    curve Predictable ZomeCallInvocation {
        cell_id: CellIdFixturator::new_indexed(Predictable, self.0.index)
            .next()
            .unwrap(),
        zome_name: ZomeNameFixturator::new_indexed(Predictable, self.0.index)
            .next()
            .unwrap(),
        cap: Some(CapSecretFixturator::new_indexed(Predictable, self.0.index)
            .next()
            .unwrap()),
        fn_name: FunctionNameFixturator::new_indexed(Predictable, self.0.index)
            .next()
            .unwrap(),
        payload: ExternInputFixturator::new_indexed(Predictable, self.0.index)
            .next()
            .unwrap(),
        provenance: AgentPubKeyFixturator::new_indexed(Predictable, self.0.index)
            .next()
            .unwrap(),
    };
);

/// Fixturator curve for a named zome invocation
/// cell id, test wasm for zome to call, function name, host input payload
pub struct NamedInvocation(pub CellId, pub TestWasm, pub String, pub ExternInput);

impl Iterator for ZomeCallInvocationFixturator<NamedInvocation> {
    type Item = ZomeCallInvocation;
    fn next(&mut self) -> Option<Self::Item> {
        let mut ret = ZomeCallInvocationFixturator::new(Unpredictable)
            .next()
            .unwrap();
        ret.cell_id = self.0.curve.0.clone();
        ret.zome_name = self.0.curve.1.clone().into();
        ret.fn_name = self.0.curve.2.clone().into();
        ret.payload = self.0.curve.3.clone();

        // simulate a local transaction by setting the cap to empty and matching the provenance of
        // the call to the cell id
        ret.cap = None;
        ret.provenance = ret.cell_id.agent_pubkey().clone();

        Some(ret)
    }
}

impl Invocation for ZomeCallInvocation {
    fn zomes(&self) -> ZomesToInvoke {
        ZomesToInvoke::One(self.zome_name.to_owned())
    }
    fn fn_components(&self) -> FnComponents {
        vec![self.fn_name.to_owned().into()].into()
    }
    fn host_input(self) -> Result<ExternInput, SerializedBytesError> {
        Ok(self.payload)
    }
}

#[derive(Clone, Constructor)]
pub struct ZomeCallHostAccess {
    pub workspace: CallZomeWorkspaceLock,
    pub keystore: KeystoreSender,
    pub network: HolochainP2pCell,
    pub signal_tx: SignalBroadcaster,
    // NB: this is kind of an odd place for this, since CellId is not really a special
    // "resource" to give access to, but rather it's a bit of data that makes sense in
    // the context of zome calls, but not every CallContext
    pub cell_id: CellId,
}

impl From<ZomeCallHostAccess> for HostAccess {
    fn from(zome_call_host_access: ZomeCallHostAccess) -> Self {
        Self::ZomeCall(zome_call_host_access)
    }
}

impl From<&ZomeCallHostAccess> for HostFnAccess {
    fn from(_: &ZomeCallHostAccess) -> Self {
        Self::all()
    }
}

/// Interface for a Ribosome. Currently used only for mocking, as our only
/// real concrete type is [WasmRibosome]
#[automock]
pub trait RibosomeT: Sized + std::fmt::Debug {
    fn dna_file(&self) -> &DnaFile;

    fn zomes_to_invoke(&self, zomes_to_invoke: ZomesToInvoke) -> Vec<ZomeName>;

    fn zome_name_to_id(&self, zome_name: &ZomeName) -> RibosomeResult<ZomeId>;

    fn maybe_call<I: Invocation + 'static>(
        &self,
        access: HostAccess,
        invocation: &I,
        zome_name: &ZomeName,
        to_call: &FunctionName,
    ) -> Result<Option<ExternOutput>, RibosomeError>;

    /// @todo list out all the available callbacks and maybe cache them somewhere
    fn list_callbacks(&self) {
        unimplemented!()
        // pseudocode
        // self.instance().exports().filter(|e| e.is_callback())
    }

    /// @todo list out all the available zome functions and maybe cache them somewhere
    fn list_zome_fns(&self) {
        unimplemented!()
        // pseudocode
        // self.instance().exports().filter(|e| !e.is_callback())
    }

    fn run_init(
        &self,
        access: InitHostAccess,
        invocation: InitInvocation,
    ) -> RibosomeResult<InitResult>;

    fn run_migrate_agent(
        &self,
        access: MigrateAgentHostAccess,
        invocation: MigrateAgentInvocation,
    ) -> RibosomeResult<MigrateAgentResult>;

    fn run_entry_defs(
        &self,
        access: EntryDefsHostAccess,
        invocation: EntryDefsInvocation,
    ) -> RibosomeResult<EntryDefsResult>;

    fn run_validation_package(
        &self,
        access: ValidationPackageHostAccess,
        invocation: ValidationPackageInvocation,
    ) -> RibosomeResult<ValidationPackageResult>;

    fn run_post_commit(
        &self,
        access: PostCommitHostAccess,
        invocation: PostCommitInvocation,
    ) -> RibosomeResult<PostCommitResult>;

    /// Helper function for running a validation callback. Just calls
    /// [`run_callback`][] under the hood.
    /// [`run_callback`]: #method.run_callback
    fn run_validate(
        &self,
        access: ValidateHostAccess,
        invocation: ValidateInvocation,
    ) -> RibosomeResult<ValidateResult>;

    fn run_validate_link<I: Invocation + 'static>(
        &self,
        access: ValidateLinkHostAccess,
        invocation: ValidateLinkInvocation<I>,
    ) -> RibosomeResult<ValidateLinkResult>;

    fn call_iterator<R: 'static + RibosomeT, I: 'static + Invocation>(
        &self,
        access: HostAccess,
        ribosome: R,
        invocation: I,
    ) -> CallIterator<R, I>;

    /// Runs the specified zome fn. Returns the cursor used by HDK,
    /// so that it can be passed on to source chain manager for transactional writes
    fn call_zome_function(
        &self,
        access: ZomeCallHostAccess,
        invocation: ZomeCallInvocation,
    ) -> RibosomeResult<ZomeCallResponse>;
}

impl std::fmt::Debug for MockRibosomeT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("MockRibosomeT()"))
    }
}

#[cfg(test)]
pub mod wasm_test {
    use crate::core::ribosome::FnComponents;
    use core::time::Duration;

    pub fn now() -> Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
    }

    #[macro_export]
    macro_rules! call_test_ribosome {
        ( $host_access:expr, $test_wasm:expr, $fn_name:literal, $input:expr ) => {{
            let mut host_access = $host_access.clone();
            let input = $input.clone();
            tokio::task::spawn(async move {
                use holochain_p2p::HolochainP2pCellT;
                // ensure type of test wasm
                use std::convert::TryInto;
                use $crate::core::ribosome::RibosomeT;

                let ribosome =
                    $crate::fixt::WasmRibosomeFixturator::new($crate::fixt::curve::Zomes(vec![
                        $test_wasm.into(),
                    ]))
                    .next()
                    .unwrap();

                let author = $crate::fixt::AgentPubKeyFixturator::new(Predictable)
                    .next()
                    .unwrap();

                // Required because otherwise the network will return routing errors
                let (_network, _r, cell_network) = crate::test_utils::test_network(
                    Some(ribosome.dna_file().dna_hash().clone()),
                    Some(author),
                )
                .await;
                let cell_id = holochain_types::cell::CellId::new(
                    cell_network.dna_hash(),
                    cell_network.from_agent(),
                );
                host_access.network = cell_network;

                let invocation = $crate::core::ribosome::ZomeCallInvocationFixturator::new(
                    $crate::core::ribosome::NamedInvocation(
                        cell_id,
                        $test_wasm.into(),
                        $fn_name.into(),
                        holochain_zome_types::ExternInput::new(input.try_into().unwrap()),
                    ),
                )
                .next()
                .unwrap();
                let zome_invocation_response =
                    match ribosome.call_zome_function(host_access, invocation.clone()) {
                        Ok(v) => v,
                        Err(e) => {
                            dbg!("call_zome_function error", &invocation, &e);
                            panic!();
                        }
                    };

                let output = match zome_invocation_response {
                    crate::core::ribosome::ZomeCallResponse::Ok(guest_output) => {
                        guest_output.into_inner().try_into().unwrap()
                    }
                    crate::core::ribosome::ZomeCallResponse::Unauthorized => unreachable!(),
                };
                output
            })
            .await
            .unwrap()
        }};
    }

    #[test]
    fn fn_components_iterate() {
        let fn_components = FnComponents::from(vec!["foo".into(), "bar".into(), "baz".into()]);
        let expected = vec!["foo_bar_baz", "foo_bar", "foo"];

        assert_eq!(fn_components.into_iter().collect::<Vec<String>>(), expected,);
    }
}

#[cfg(test)]
#[cfg(feature = "slow_tests")]
mod slow_tests {

    #[tokio::test(threaded_scheduler)]
    async fn warm_wasm_tests() {
        crate::test_utils::warm_wasm_tests();
    }
}
