use crate::prelude::*;

fixturator!(bool, self: this, false, rand::random(), {
    this.0.index += 1;
    this.0.index % 2 != 0
});

basic_test!(
    bool,
    vec![false; 40],
    vec![true, false]
        .into_iter()
        .cycle()
        .take(20)
        .collect::<Vec<bool>>()
);
