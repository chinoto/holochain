/// Thin wrapper around update! for app entries.
/// The hash evalutes to the HeaderHash of the deleted element, the input is the new app entry.
///
/// Updates can reference create and update elements (header+entry) but not deletes.
///
/// As updates can reference elements on other agent's source chains across unpredictable network
/// topologies, they are treated as a tree structure.
///
/// Many updates can point to a single create/update and continue to accumulate as long as agents
/// author them against that element. It is up to happ developers to decide how to ensure the tree
/// branches are walked appropriately and that updates point to the correct element, whatever that
/// means for the happ.
///
/// ```ignore
/// #[hdk_entry(id = "foo")]
/// struct Foo(u32);
///
/// let foo_zero_header_hash: HeaderHash = commit_entry!(Foo(0))?;
/// let foo_ten_update_header_hash: HeaderHash = update_entry!(foo_zero_header_hash, Foo(10))?;
/// ```
///
/// @todo in the future this will be true because we will have the concept of 'redirects':
/// Works as an app entry delete+create.
///
/// @see create_entry!
/// @see update!
/// @see delete_entry!
#[macro_export]
macro_rules! update_entry {
    ( $hash:expr, $input:expr ) => {{
        let try_sb = $crate::prelude::SerializedBytes::try_from($input);
        match try_sb {
            Ok(sb) => update!(
                $hash,
                $input.into(),
                $crate::prelude::Entry::App(sb.try_into()?)
            ),
            Err(e) => Err(e),
        }
    }};
}
