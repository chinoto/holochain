use hdk3::prelude::*;

#[hdk_extern]
fn zome_info(_: ()) -> ExternResult<ZomeInfoOutput> {
    Ok(ZomeInfoOutput::new(zome_info!()?))
}
